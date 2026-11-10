<#
.SYNOPSIS
Continuously reads Sysmon Event 1/3 and submits local batches to Aegis-ON.
.DESCRIPTION
Experimental: Windows execution has not yet been verified. It reads the local
Sysmon Operational channel; it does not install Sysmon or change its config.
Use a private cursor path outside the repository. The API token is read only
from AEGIS_API_TOKEN and must not be passed on the command line.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$CollectorId,
    [Parameter(Mandatory=$true)][string]$CursorPath,
    [ValidateRange(1,60)][int]$IntervalSeconds = 5,
    [ValidateRange(1,100)][int]$BatchSize = 20,
    [ValidateRange(1,65535)][int]$Port = 8000
)
$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-Sysmon/Operational'
$names = @('UtcTime','Image','CommandLine','ParentImage','ParentCommandLine','User','ProcessGuid','ProcessId','SourceIp','SourcePort','DestinationIp','DestinationPort','Initiated')
if ([string]::IsNullOrWhiteSpace($env:AEGIS_API_TOKEN)) { throw 'Set AEGIS_API_TOKEN in the environment first.' }
$base = "http://127.0.0.1:$Port"
$headers = @{ Authorization = "Bearer $env:AEGIS_API_TOKEN" }
$cursor = [IO.Path]::GetFullPath($CursorPath)
$dir = [IO.Path]::GetDirectoryName($cursor)
if (-not [IO.Directory]::Exists($dir)) { throw 'Cursor directory does not exist.' }
# Exclusive lease prevents two local instances sharing a checkpoint.
$lease = [IO.File]::Open("$cursor.lock", [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
function Send-Heartbeat([string]$state, [string]$code = $null) {
    $body = @{state=$state; error_code=$code} | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Method Post -Uri "$base/api/v1/collectors/$CollectorId/heartbeat" -Headers $headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 10 | Out-Null } catch { Write-Warning 'Collector heartbeat failed; retrying.' }
}
function Write-Cursor([long]$id) {
    $temporary = "$cursor.tmp"
    [IO.File]::WriteAllText($temporary, [string]$id, [Text.Encoding]::ASCII)
    if ([IO.File]::Exists($cursor)) { [IO.File]::Replace($temporary, $cursor, $null) }
    else { [IO.File]::Move($temporary, $cursor) }
}
function Get-ChannelEdge([switch]$Oldest) {
    try {
        $arguments = @{LogName=$channel; MaxEvents=1; ErrorAction='Stop'}
        if ($Oldest) { $arguments.Oldest = $true }
        return Get-WinEvent @arguments
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return $null }
        throw
    }
}
$reportedFailure = $false
try {
    if ([IO.File]::Exists($cursor)) {
        $text = [IO.File]::ReadAllText($cursor).Trim()
        [long]$last = 0
        if (-not [long]::TryParse($text, [ref]$last) -or $last -lt 0) { throw 'Invalid checkpoint; stop and investigate.' }
    } else {
        # Start after the newest existing record; never silently ingest historical logs.
        $newest = Get-ChannelEdge
        [long]$last = if ($null -eq $newest) { 0 } else { $newest.RecordId }
        Write-Cursor $last
        Write-Host 'Initialized at the current channel position. Earlier records were not collected.'
    }
    while ($true) {
        try {
            $newest = Get-ChannelEdge
            $oldest = Get-ChannelEdge -Oldest
            if ($last -gt 0 -and (($null -eq $newest) -or $newest.RecordId -lt $last -or ($oldest.RecordId -gt ($last + 1)))) {
                Send-Heartbeat 'error' 'read_error'
                throw 'Channel was cleared or retained records may have rolled over. Stop and investigate the checkpoint.'
            }
            $pending = "$cursor.pending"
            $endFilter = ''
            if ([IO.File]::Exists($pending)) {
                $pendingData = [IO.File]::ReadAllText($pending).Trim().Split(',')
                [long]$pendingFirst = 0; [long]$pendingEnd = 0; [int]$pendingCount = 0
                if ($pendingData.Count -ne 3 -or -not [long]::TryParse($pendingData[0], [ref]$pendingFirst) -or -not [long]::TryParse($pendingData[1], [ref]$pendingEnd) -or -not [int]::TryParse($pendingData[2], [ref]$pendingCount) -or $pendingFirst -le 0 -or $pendingEnd -lt $pendingFirst -or $pendingCount -le 0 -or $pendingCount -gt 100) { throw 'Invalid pending batch checkpoint.' }
                if ($pendingEnd -le $last) { [IO.File]::Delete($pending) }
                else { $endFilter = " and EventRecordID <= $pendingEnd" }
            }
            $xpath = "*[System[(EventID=1 or EventID=3) and EventRecordID > $last$endFilter]]"
            $readLimit = if ($endFilter) { $pendingCount } else { $BatchSize }
            try { $records = @(Get-WinEvent -LogName $channel -FilterXPath $xpath -Oldest -MaxEvents $readLimit -ErrorAction Stop) }
            catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $records = @() } else { throw } }
            if ($endFilter -and ($records.Count -ne $pendingCount -or $records[0].RecordId -ne $pendingFirst -or $records[-1].RecordId -ne $pendingEnd)) { throw 'Pending batch is incomplete; stop to prevent data loss.' }
            if ($records.Count -gt 0) {
                if (-not $endFilter) {
                    # Store only record identifiers, never the original events, before sending.
                    [IO.File]::WriteAllText($pending, "$($records[0].RecordId),$($records[-1].RecordId),$($records.Count)", [Text.Encoding]::ASCII)
                }
                $events = @(foreach ($record in $records) {
                    [xml]$xml = $record.ToXml(); $fields = [ordered]@{}
                    foreach ($name in $names) { $fields[$name] = '' }
                    foreach ($node in $xml.Event.EventData.Data) { $name = $node.GetAttribute('Name'); if ($fields.Contains($name)) { $fields[$name] = $node.InnerText } }
                    [ordered]@{ System=[ordered]@{ Provider=$record.ProviderName; EventID=$record.Id; TimeCreated=$record.TimeCreated.ToUniversalTime().ToString('o'); Computer=$record.MachineName; EventRecordID=$record.RecordId; Channel=$record.LogName }; EventData=$fields }
                })
                $json = ConvertTo-Json -InputObject ([ordered]@{events=$events}) -Depth 6 -Compress
                $bytes = [Text.Encoding]::UTF8.GetBytes($json)
                if ($bytes.Length -gt 2097152) { [IO.File]::Delete($pending); Send-Heartbeat 'error' 'export_error'; throw 'Batch exceeds 2 MiB; reduce batch size and investigate.' }
                $first = $records[0].RecordId; $end = $records[-1].RecordId
                $requestHeaders = @{Authorization=$headers.Authorization; 'X-Collector-ID'=$CollectorId; 'Idempotency-Key'="sysmon-$first-$end"}
                # Retry an identical batch on the next loop after failure; never advance before ACK.
                try { $response = Invoke-RestMethod -Method Post -Uri "$base/api/v1/ingest/sysmon" -Headers $requestHeaders -ContentType 'application/json' -Body $bytes -TimeoutSec 30 }
                catch { Send-Heartbeat 'error' 'send_error'; Write-Warning 'Submission failed; the checkpoint was not advanced. Retrying.'; Start-Sleep -Seconds $IntervalSeconds; continue }
                if (-not $response.analysis_id) { throw 'Server did not acknowledge analysis; checkpoint unchanged.' }
                Write-Cursor $end; $last = $end; [IO.File]::Delete($pending)
                Write-Host "Acknowledged $($records.Count) events; checkpoint advanced."
            }
            Send-Heartbeat 'running'
        } catch {
            $reportedFailure = $true; Send-Heartbeat 'error' 'read_error'
            throw 'Collection stopped. Check channel availability, rollover, input size and checkpoint; no raw log was printed.'
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
} finally { if (-not $reportedFailure) { Send-Heartbeat 'stopped' }; $lease.Dispose() }
