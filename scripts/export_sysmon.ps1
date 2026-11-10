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
if (Test-Path -LiteralPath $OutputPath) { throw 'Output already exists; choose a new file.' }
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
# Windows PowerShell adds a UTF-8 BOM and Set-Content appends a newline.
# Use a conservative 5-byte allowance before creating any output file.
$estimatedBytes = [System.Text.Encoding]::UTF8.GetByteCount($json) + 5
if ($estimatedBytes -gt (2 * 1024 * 1024)) {
    throw 'Export exceeds the 2 MiB API limit; select fewer events.'
}
Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
Write-Host "Exported $($events.Count) Sysmon events to $OutputPath"
