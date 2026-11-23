[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')]
    [string]$StartUtc,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')]
    [string]$EndUtc,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Z0-9-]+$')]
    [string]$SharedHostIdentifier,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$start = [DateTime]::Parse($StartUtc).ToUniversalTime()
$end = [DateTime]::Parse($EndUtc).ToUniversalTime()
if ($end -lt $start) { throw 'EndUtc must be greater than or equal to StartUtc.' }

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

function Convert-SysmonEvent {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Record)
    [xml]$xml = $Record.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }
    [pscustomobject]@{
        UtcTime = $Record.TimeCreated.ToUniversalTime().ToString('o')
        host_identifier = $SharedHostIdentifier
        EventRecordID = [int64]$Record.RecordId
        EventID = [int]$Record.Id
        ProcessGuid = $data['ProcessGuid']
        Image = $data['Image']
        ParentImage = $data['ParentImage']
        CommandLine = $data['CommandLine']
        SourceIp = $data['SourceIp']
        DestinationIp = $data['DestinationIp']
        DestinationPort = $data['DestinationPort']
    }
}

foreach ($id in 1, 3) {
    $records = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $id
        StartTime = $start
        EndTime = $end
    } | ForEach-Object { Convert-SysmonEvent $_ })

    $payload = [pscustomobject]@{
        exported_at_utc = [DateTime]::UtcNow.ToString('o')
        requested_window_utc = [pscustomobject]@{ start = $StartUtc; end = $EndUtc }
        event_id = $id
        source_host = $SharedHostIdentifier
        redaction_required_before_sharing = @('CommandLine secrets', 'SourceIp', 'DestinationIp')
        events = $records
    }
    $payload | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -Path (Join-Path $OutputDirectory ("sysmon_event_{0}.json" -f $id))
}
