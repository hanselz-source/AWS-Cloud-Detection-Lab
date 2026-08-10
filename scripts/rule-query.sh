#!/usr/bin/env bash
# prints the query for one detection. IT DOES NOT RUN, placeholders used
#
# converts detections/<name>/rule.yml with the core pipeline.
# adds the rule's own pipeline.yml when the folder holds one.
#
# running a query needs an engine address and a password.
#
# usage:
#   ./scripts/rule-query.sh iam-backdoor-user splunk
#   ./scripts/rule-query.sh iam-backdoor-user kusto

set -euo pipefail

# set this to the repo root.
# the commented line works it out from where this script sits.
REPO_ROOT="<PATH_TO_REPO>/cloud-detection-lab"
# REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

name=${1:-}
target=${2:-}

if [ -z "$name" ] || [ -z "$target" ]; then
  echo "usage: $(basename "$0") <detection-name> <splunk|kusto>" >&2
  exit 2
fi

case "$target" in
  *)      echo "target must be splunk or kusto" >&2; exit 2 ;;
esac

dir="$REPO_ROOT/detections/$name"
[ -d "$dir" ] || { echo "no detection named $name" >&2; exit 2; }

args=(convert -t "$target" -p "$REPO_ROOT/core_pipelines/$core")

if [ -f "$dir/pipeline.yml" ]; then
  args+=(-p "$dir/pipeline.yml")
fi

args+=("$dir/rule.yml")

query=$(sigma "${args[@]}" 2>/dev/null)

if [ -z "${query//[[:space:]]/}" ]; then
  echo "conversion produced no query, rerunning to show the error" >&2
  sigma "${args[@]}"
  exit 1
fi

# another field. this appends it after conversion, so ci never checks it.
if [ -s "$dir/$refine" ]; then
  query="$query"$'\n'"$(cat "$dir/$refine")"
fi

printf '%s\n' "$query"
