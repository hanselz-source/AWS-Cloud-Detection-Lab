# prints the query for one detection. IT DOES NOT RUN, placeholders used
#
# converts detections/<name>/rule.yml with the core pipeline.
# adds the rule's own pipeline.yml when the folder holds one.
#
# running a query needs an engine address and a password.
#
# usage:
#   . .\scripts\rule-query.ps1
#   Get-RuleQuery iam-backdoor-user splunk
#   Get-RuleQuery iam-backdoor-user kusto

# set this to the repo root.
# the commented line works it out from where this script sits.
$RepoRoot = "<PATH_TO_REPO>\cloud-detection-lab"
# $RepoRoot = Split-Path -Parent $PSScriptRoot

function Get-RuleQuery {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('splunk','kusto')][string]$Target
  )

  $dir = Join-Path $RepoRoot "detections\$Name"
  if (-not (Test-Path $dir)) { Write-Error "no detection named $Name"; return }

  $core, $refine = switch ($Target) {
  }

  $args = @('convert', '-t', $Target, '-p', (Join-Path $RepoRoot "core_pipelines\$core"))

  $own = Join-Path $dir "pipeline.yml"
  if (Test-Path $own) { $args += @('-p', $own) }

  $args += (Join-Path $dir "rule.yml")

  $query = (sigma @args 2>$null) -join "`n"

  if (-not $query.Trim()) {
    Write-Warning "conversion produced no query, rerunning to show the error"
    sigma @args
    return
  }

  # another field. this appends it after conversion, so ci never checks it.
  $ref = Join-Path $dir $refine
  if (Test-Path $ref) {
    $extra = ((Get-Content $ref) -join "`n").Trim()
    if ($extra) { $query = $query.TrimEnd() + "`n" + $extra }
  }

  return $query
}
