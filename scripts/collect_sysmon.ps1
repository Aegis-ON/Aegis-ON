<#
.SYNOPSIS
Continuously reads Sysmon Event 1/3 and submits local batches to Aegis-ON.
.DESCRIPTION
Experimental: Windows execution has not yet been verified. It reads the local
Sysmon Operational channel; it does not install Sysmon or change its config.
Use a private cursor path outside the repository. Provision the individual
collector credential once with -InitializeCredential; it is protected by the
Windows current-user DPAPI and can only be opened by that same Windows account.
Running as a service therefore requires provisioning as that service identity.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$CollectorId,
    [Parameter(Mandatory=$true)][string]$CursorPath,
    [ValidateRange(1,60)][int]$IntervalSeconds = 5,
    [ValidateRange(1,100)][int]$BatchSize = 20,
    [ValidateRange(1,65535)][int]$Port = 8000,
    [string]$ServerUrl = '',
    [switch]$AdoptExistingCursor,
    [string]$CredentialPath = '',
    [switch]$InitializeCredential,
    [switch]$UseLegacySharedToken
)
$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-Sysmon/Operational'
$names = @('UtcTime','Image','CommandLine','ParentImage','ParentCommandLine','User','ProcessGuid','ProcessId','SourceIp','SourcePort','DestinationIp','DestinationPort','Initiated')
if ($UseLegacySharedToken) {
    if ($InitializeCredential -or $CredentialPath) { throw 'Legacy token and credential file options cannot be combined.' }
    if ([string]::IsNullOrWhiteSpace($env:AEGIS_API_TOKEN)) { throw 'Set AEGIS_API_TOKEN for explicitly enabled legacy mode.' }
    Write-Warning 'Legacy shared-token collection requires explicit server configuration and does not authenticate an individual collector.'
    $collectorSecret = $env:AEGIS_API_TOKEN
} else {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Collector credential protection requires Windows DPAPI.' }
    if ([string]::IsNullOrWhiteSpace($CredentialPath)) { throw 'Set CredentialPath to a private location outside the repository.' }
    $credentialFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CredentialPath)
    if ($InitializeCredential) {
        if ([IO.File]::Exists($credentialFile)) { throw 'Credential file already exists; do not overwrite it.' }
        $secure = Read-Host 'Enter the collector credential issued by the server' -AsSecureString
        if ($secure.Length -eq 0) { throw 'Credential cannot be empty.' }
        # On Windows without -Key, ConvertFrom-SecureString uses current-user DPAPI.
        $protected = ConvertFrom-SecureString -SecureString $secure
        $file = [IO.File]::Open($credentialFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $writer = [IO.StreamWriter]::new($file, [Text.Encoding]::ASCII); try { $writer.Write($protected) } finally { $writer.Dispose() } }
        finally { $file.Dispose(); $secure.Dispose() }
        Write-Host 'Encrypted credential saved for this Windows account. Keep the file private.'
        exit 0
    }
    try {
        $secure = ConvertTo-SecureString ([IO.File]::ReadAllText($credentialFile).Trim())
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $collectorSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $secure.Dispose() }
        if ([string]::IsNullOrWhiteSpace($collectorSecret)) { throw 'Empty credential.' }
    } catch { throw 'Unable to open collector credential with this Windows account.' }
}
if ([string]::IsNullOrWhiteSpace($ServerUrl)) { $ServerUrl = "http://127.0.0.1:$Port" }
$server = $null
if (-not [Uri]::TryCreate($ServerUrl, [System.UriKind]::Absolute, [ref]$server) -or
    ($server.Scheme -ne 'https' -and -not ($server.Scheme -eq 'http' -and $server.IsLoopback)) -or
    $server.UserInfo -or $server.Query -or $server.Fragment -or $server.AbsolutePath -ne '/') {
    throw 'ServerUrl must be an HTTPS origin or a loopback HTTP origin, without credentials, path, query or fragment.'
}
$base = $server.GetLeftPart([System.UriPartial]::Authority).TrimEnd('/')
$headers = @{ Authorization = "Bearer $collectorSecret"; 'X-Collector-ID' = $CollectorId }
$cursor = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CursorPath)
$dir = [IO.Path]::GetDirectoryName($cursor)
if (-not [IO.Directory]::Exists($dir)) { throw 'Cursor directory does not exist.' }
# Exclusive lease prevents two local instances sharing a checkpoint.
$lease = [IO.File]::Open("$cursor.lock", [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
function Send-Heartbeat([string]$state, $code = $null) {
    $body = @{state=$state; error_code=$code} | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Method Post -Uri "$base/api/v1/collectors/$CollectorId/heartbeat" -Headers $headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 10 -MaximumRedirection 0 | Out-Null } catch { Write-Warning 'Collector heartbeat failed; retrying.' }
}
function Write-Cursor([long]$id) {
    $temporary = "$cursor.tmp"
    [IO.File]::WriteAllText($temporary, [string]$id, [Text.Encoding]::ASCII)
    if ([IO.File]::Exists($cursor)) { [IO.File]::Replace($temporary, $cursor, [System.Management.Automation.Language.NullString]::Value) }
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
    # Bind the checkpoint to its collector identity and destination. Reusing a
    # cursor for a different server would silently skip the earlier records.
    $binding = "$cursor.binding"
    $hadBinding = [IO.File]::Exists($binding)
    $hasCursor = [IO.File]::Exists($cursor)
    $hasPending = [IO.File]::Exists("$cursor.pending")
    if (-not $hasCursor -and ($hadBinding -or $hasPending)) {
        throw 'Checkpoint is missing while binding or pending metadata exists; investigate before resuming.'
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $bindingBytes = [Text.Encoding]::UTF8.GetBytes("$CollectorId`n$base")
        $expectedBinding = ([BitConverter]::ToString($hash.ComputeHash($bindingBytes))).Replace('-', '').ToLowerInvariant()
    } finally { $hash.Dispose() }
    if ($hadBinding) {
        if ([IO.File]::ReadAllText($binding).Trim() -ne $expectedBinding) {
            throw 'Checkpoint belongs to a different collector or server; use a separate checkpoint.'
        }
    } else {
        if ($hasCursor -and -not $AdoptExistingCursor) {
            throw 'Existing checkpoint has no binding; verify its original server and collector, then use -AdoptExistingCursor.'
        }
        if ($hasCursor) { Write-Warning 'Adopting a legacy cursor; the operator must verify its original collector and server.' }
        [IO.File]::WriteAllText($binding, $expectedBinding, [Text.Encoding]::ASCII)
    }
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
        $failureCode = 'read_error'
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
                if ($bytes.Length -gt 2097152) { [IO.File]::Delete($pending); $failureCode = 'export_error'; throw 'Batch exceeds 2 MiB; reduce batch size and investigate.' }
                $first = $records[0].RecordId; $end = $records[-1].RecordId
                $requestHeaders = @{Authorization=$headers.Authorization; 'X-Collector-ID'=$CollectorId; 'Idempotency-Key'="sysmon-$first-$end"}
                # Retry an identical batch on the next loop after failure; never advance before ACK.
                try { $response = Invoke-RestMethod -Method Post -Uri "$base/api/v1/ingest/sysmon" -Headers $requestHeaders -ContentType 'application/json' -Body $bytes -TimeoutSec 30 -MaximumRedirection 0 }
                catch {
                    $httpCode = 0
                    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                        $httpCode = [int]$_.Exception.Response.StatusCode
                    }
                    if ($httpCode -ge 400 -and $httpCode -lt 500 -and $httpCode -ne 429) {
                        $failureCode = 'invalid_input'
                        throw 'Server rejected the batch or authentication; checkpoint unchanged. Investigate before retrying.'
                    }
                    Send-Heartbeat 'error' 'send_error'; Write-Warning 'Submission failed; the checkpoint was not advanced. Retrying.'; Start-Sleep -Seconds $IntervalSeconds; continue
                }
                if (-not $response.analysis_id) { throw 'Server did not acknowledge analysis; checkpoint unchanged.' }
                Write-Cursor $end; $last = $end; [IO.File]::Delete($pending)
                Write-Host "Acknowledged $($records.Count) events; checkpoint advanced."
            }
            Send-Heartbeat 'running'
        } catch {
            $reportedFailure = $true; Send-Heartbeat 'error' $failureCode
            throw 'Collection stopped. Check channel availability, rollover, input size and checkpoint; no raw log was printed.'
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
} catch {
    if (-not $reportedFailure) { Send-Heartbeat 'error' 'read_error' }
    $reportedFailure = $true
    throw
} finally { if (-not $reportedFailure) { Send-Heartbeat 'stopped' }; $lease.Dispose() }

