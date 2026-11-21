$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$file = (Resolve-Path './scripts/collect_sysmon.ps1').Path
$ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Collector script has parse errors' }
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($name in 'Write-Cursor', 'Send-Heartbeat') {
    $match = $functions | Where-Object { $_.Name -eq $name }
    if ($null -eq $match) { throw 'Collector function not found' }
    Invoke-Expression $match.Extent.Text
}
$cursor = Join-Path ([IO.Path]::GetTempPath()) ('aegis-test-' + [guid]::NewGuid().ToString())
try {
    Write-Cursor 7
    Write-Cursor 8
    if ((Get-Content -LiteralPath $cursor -Raw) -ne '8') { throw 'Cursor replacement failed' }
} finally {
    Remove-Item -LiteralPath $cursor -ErrorAction SilentlyContinue
}
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $ContentType, $Body, $TimeoutSec, $MaximumRedirection)
    $script:payload = [Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json
}
$base = 'http://localhost'
$CollectorId = 'test'
$headers = @{}
Send-Heartbeat 'running'
if ($payload.state -ne 'running' -or $null -ne $payload.error_code) { throw 'Running heartbeat must have null error code' }
Send-Heartbeat 'error' 'read_error'
if ($payload.state -ne 'error' -or $payload.error_code -ne 'read_error') { throw 'Error heartbeat missing code' }
Write-Host 'Windows collector regression checks passed'
