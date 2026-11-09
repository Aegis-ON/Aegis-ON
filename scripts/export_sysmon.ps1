<#
.SYNOPSIS
Exports up to 1000 Sysmon Event 1 and 3 records to the Aegis-ON JSON format.
.EXAMPLE
./scripts/export_sysmon.ps1 -OutputPath ./sysmon-export.json -MaxEvents 500
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [ValidateRange(1, 1000)][int]$MaxEvents = 1000
)

$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-Sysmon/Operational'
$names = @('UtcTime', 'Image', 'CommandLine', 'ParentImage', 'ParentCommandLine',
    'User', 'ProcessGuid', 'ProcessId', 'SourceIp', 'SourcePort', 'DestinationIp', 'DestinationPort', 'Initiated')

try {
    $records = @(Get-WinEvent -FilterHashtable @{ LogName = $channel; Id = @(1, 3) } -MaxEvents $MaxEvents -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $records = @() }
    else { throw }
}

$events = @(
    foreach ($record in $records) {
        [xml]$xml = $record.ToXml()
        $fields = [ordered]@{}
        foreach ($name in $names) { $fields[$name] = '' }
        foreach ($node in $xml.Event.EventData.Data) {
            $name = $node.GetAttribute('Name')
            if ($fields.Contains($name)) { $fields[$name] = $node.InnerText }
        }
        $time = if ($null -eq $record.TimeCreated) { '' } else { $record.TimeCreated.ToUniversalTime().ToString('o') }
        [ordered]@{
            System = [ordered]@{
                Provider = $record.ProviderName
                EventID = $record.Id
                TimeCreated = $time
                Computer = $record.MachineName
                EventRecordID = $record.RecordId
                Channel = $record.LogName
            }
            EventData = $fields
        }
    }
)

if ($events.Count -eq 0) { throw 'No matching Sysmon Event 1 or 3 records were found.' }
$json = ConvertTo-Json -InputObject ([ordered]@{ events = $events }) -Depth 6
Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
Write-Host "Exported $($events.Count) Sysmon events to $OutputPath"
