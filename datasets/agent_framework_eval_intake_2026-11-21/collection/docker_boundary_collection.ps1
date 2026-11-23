# Run from the isolated Windows Docker host. Export only lab data and redact before sharing.
# No framework command belongs in this collector; start the approved lab separately.
param(
  [Parameter(Mandatory = $true)][string]$CaseId,
  [Parameter(Mandatory = $true)][string]$NetworkName,
  [Parameter(Mandatory = $true)][string[]]$ContainerName,
  [Parameter(Mandatory = $true)][string]$OutputDirectory,
  [datetime]$SinceUtc = (Get-Date).ToUniversalTime().AddMinutes(-10),
  [datetime]$UntilUtc = (Get-Date).ToUniversalTime()
)

$ErrorActionPreference = 'Stop'
$casePath = Join-Path $OutputDirectory $CaseId
New-Item -ItemType Directory -Force -Path $casePath | Out-Null

$network = docker network inspect $NetworkName | ConvertFrom-Json
if (-not $network[0].Internal) {
  throw "Refusing collection: Docker network '$NetworkName' is not internal."
}

$network | ConvertTo-Json -Depth 12 | Set-Content -Encoding utf8 (Join-Path $casePath 'docker_network_raw.json')

foreach ($name in $ContainerName) {
  $inspect = docker inspect $name | ConvertFrom-Json
  $inspect | ConvertTo-Json -Depth 16 | Set-Content -Encoding utf8 (Join-Path $casePath ("{0}_inspect_raw.json" -f $name))
  docker logs $name 2>&1 | Set-Content -Encoding utf8 (Join-Path $casePath ("{0}_stdout_stderr_raw.log" -f $name))
  docker top $name -eo pid,ppid,comm,args 2>&1 | Set-Content -Encoding utf8 (Join-Path $casePath ("{0}_processes_raw.log" -f $name))
  docker events --since $SinceUtc.ToString('o') --until $UntilUtc.ToString('o') --filter type=container --filter container=$name --format '{{json .}}' |
    Set-Content -Encoding utf8 (Join-Path $casePath ("{0}_lifecycle_raw.jsonl" -f $name))
}

@{
  case_id = $CaseId
  collected_utc = (Get-Date).ToUniversalTime().ToString('o')
  network_internal_verified = $true
  containers = $ContainerName
  required_redaction = @('container IDs', 'container IPs', 'MAC addresses', 'host paths', 'tokens', 'passwords', 'installation IDs')
  note = 'Docker Desktop Linux VM PIDs must not be joined directly to Windows Sysmon PIDs.'
} | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $casePath 'collection_metadata.json')
