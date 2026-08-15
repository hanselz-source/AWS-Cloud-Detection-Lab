#!/usr/bin/env python3
"""Evaluate the generated SPL/KQL subset against CloudTrail JSON fixtures."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path
from typing import Any


MISSING = object()


def records(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(document, dict) and isinstance(document.get("Records"), list):
        events = document["Records"]
    elif isinstance(document, dict):
        events = [document]
    else:
        raise ValueError(f"{path} is not a JSON object or CloudTrail Records document")
    if not all(isinstance(event, dict) for event in events):
        raise ValueError(f"{path} contains a non-object record")
    return events


def values_at(value: Any, path: str) -> list[Any]:
    parts = [part.removesuffix("{}") for part in path.split(".") if part]
    values = [value]
    for part in parts:
        next_values: list[Any] = []
        for current in values:
            if isinstance(current, dict) and part in current:
                child = current[part]
                next_values.extend(child if isinstance(child, list) else [child])
            elif isinstance(current, list):
                for item in current:
                    if isinstance(item, dict) and part in item:
                        child = item[part]
                        next_values.extend(child if isinstance(child, list) else [child])
        values = next_values
    return values


def splunk_values(event: dict[str, Any], field: str) -> list[Any]:
    if field == "index":
        return ["main"]
    if field == "sourcetype":
        return ["aws:cloudtrail"]
    return values_at(event, field)


def unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return json.loads(value)
    return value


def compare(actual: Any, operator: str, expected: Any) -> bool:
    if actual is MISSING or actual is None:
        return False
    if operator == "=":
        if isinstance(expected, str) and "*" in expected:
            return fnmatch.fnmatchcase(str(actual), expected)
        return str(actual) == str(expected)
    if operator == "!=":
        return str(actual) != str(expected)
    try:
        left_number = float(actual)
        right_number = float(expected)
    except (TypeError, ValueError):
        return False
    if operator == "<=":
        return left_number <= right_number
    if operator == ">=":
        return left_number >= right_number
    if operator == "<":
        return left_number < right_number
    if operator == ">":
        return left_number > right_number
    return False


SPL_TOKEN = re.compile(
    r'^(?:"(?P<quoted_field>[^"]+)"|(?P<field>[^=<>!\s]+))'
    r'(?P<operator><=|>=|!=|=|<|>)'
    r'(?P<value>"(?:\\.|[^"\\])*"|.+)$'
)


def splunk_match(event: dict[str, Any], query: str) -> bool:
    query = query.strip()
    branches = re.split(r"\s+OR\s+", query, flags=re.IGNORECASE)
    for branch in branches:
        terms = re.findall(r'"[^"\\]*(?:\\.[^"\\]*)*"=?(?:"[^"\\]*(?:\\.[^"\\]*)*"|\S+)|\S+', branch)
        if not terms:
            continue
        if all(splunk_term(event, term) for term in terms):
            return True
    return False


def splunk_term(event: dict[str, Any], term: str) -> bool:
    match = SPL_TOKEN.match(term)
    if not match:
        raise ValueError(f"unsupported SPL term: {term}")
    field = match.group("quoted_field") or match.group("field")
    operator = match.group("operator")
    expected_text = match.group("value")
    expected = unquote(expected_text)
    return any(compare(actual, operator, expected) for actual in splunk_values(event, field))


def kusto_row(event: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "EventSource": event.get("eventSource"),
        "EventName": event.get("eventName"),
        "UserIdentityType": values_at(event, "userIdentity.type")[0]
        if values_at(event, "userIdentity.type")
        else None,
    }
    for source, target in (
        ("requestParameters", "RequestParameters"),
        ("responseElements", "ResponseElements"),
        ("additionalEventData", "AdditionalEventData"),
    ):
        value = event.get(source)
        row[target] = json.dumps(value, separators=(",", ":")) if value is not None else None
    return row


KQL_TOKEN = re.compile(
    r'\s*(?:(?P<string>"(?:\\.|[^"\\])*")|(?P<number>-?\d+(?:\.\d+)?)|'
    r'(?P<operator>=~|==|!=|<=|>=|<|>)|(?P<word>[A-Za-z_]\w*)|(?P<punct>[().]))'
)


def kql_tokens(expression: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(expression):
        match = KQL_TOKEN.match(expression, position)
        if not match:
            raise ValueError(f"unsupported KQL syntax near: {expression[position:position + 30]}")
        tokens.append(next(value for value in match.groups() if value is not None))
        position = match.end()
    return tokens


class KqlParser:
    def __init__(self, tokens: list[str], row: dict[str, Any]):
        self.tokens = tokens
        self.position = 0
        self.row = row

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None or (expected is not None and token.lower() != expected.lower()):
            raise ValueError(f"expected {expected or 'token'}, got {token}")
        self.position += 1
        return token

    def boolean(self) -> bool:
        value = self.kql_or()
        if self.peek() is not None:
            raise ValueError(f"unexpected KQL token: {self.peek()}")
        return value

    def kql_or(self) -> bool:
        value = self.kql_and()
        while self.peek() and self.peek().lower() == "or":
            self.take()
            value = self.kql_and() or value
        return value

    def kql_and(self) -> bool:
        value = self.kql_atom()
        while self.peek() and self.peek().lower() == "and":
            self.take()
            value = self.kql_atom() and value
        return value

    def kql_atom(self) -> bool:
        if self.peek() == "(":
            self.take("(")
            value = self.kql_or()
            self.take(")")
            return value
        left = self.operand()
        operator = self.take().lower()
        right = self.operand(literal=True)
        return kql_compare(left, operator, right)

    def operand(self, literal: bool = False) -> Any:
        token = self.take()
        if token.startswith('"'):
            return json.loads(token)
        if re.fullmatch(r"-?\d+(?:\.\d+)?", token):
            return float(token) if "." in token else int(token)
        if literal:
            raise ValueError(f"unsupported KQL literal: {token}")
        if token.lower() == "parse_json":
            self.take("(")
            source = self.take()
            self.take(")")
            value = self.row.get(source)
            if isinstance(value, str):
                value = json.loads(value)
            while self.peek() == ".":
                self.take(".")
                value = child_values(value, self.take())
            return value
        value = self.row.get(token, MISSING)
        while self.peek() == ".":
            self.take(".")
            value = child_values(value, self.take())
        return value


def child_values(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        return value.get(key, MISSING)
    if isinstance(value, list):
        return [item[key] for item in value if isinstance(item, dict) and key in item]
    return MISSING


def iterable_values(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def kql_compare(actual: Any, operator: str, expected: Any) -> bool:
    if actual is MISSING or actual is None:
        return False
    actual_values = iterable_values(actual)
    if operator in {"=~", "==", "="}:
        return any(str(value).casefold() == str(expected).casefold() for value in actual_values)
    if operator == "contains":
        expected_text = str(expected).casefold()
        return any(expected_text in json.dumps(value, separators=(",", ":")).casefold() for value in actual_values)
    return any(compare(value, operator, expected) for value in actual_values)


def kusto_match(event: dict[str, Any], query: str) -> bool:
    marker = "| where"
    if marker not in query.lower():
        raise ValueError("KQL query has no where clause")
    expression = re.split(r"\|\s*where\s+", query, maxsplit=1, flags=re.IGNORECASE)[1].strip()
    return KqlParser(kql_tokens(expression), kusto_row(event)).boolean()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("splunk", "kusto"), required=True)
    parser.add_argument("--query", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--expect", choices=("tp", "tn"), required=True)
    args = parser.parse_args()

    query = args.query.read_text(encoding="utf-8")
    events = records(args.fixture)
    matcher = splunk_match if args.backend == "splunk" else kusto_match
    matched = [event.get("eventID", "<no eventID>") for event in events if matcher(event, query)]
    passed = bool(matched) if args.expect == "tp" else not matched
    status = "ok" if passed else "FAIL"
    print(f"{status} {args.backend} {args.expect} {args.fixture} matches={len(matched)}")
    if matched:
        print("  " + " ".join(matched))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, json.JSONDecodeError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        raise SystemExit(2)
