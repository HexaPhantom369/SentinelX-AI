[CmdletBinding()]
param(
    [ValidateRange(1, 60)]
    [int]$PollSeconds = 10,
    [ValidateRange(1, 1440)]
    [int]$LookbackMinutes = 10,
    [ValidateRange(1, 100)]
    [int]$BatchSize = 100
)

$ErrorActionPreference = "Stop"
$apiBase = if ($env:SENTINELX_API_BASE) { $env:SENTINELX_API_BASE.TrimEnd("/") } else { "http://127.0.0.1:5000" }
$token = $env:SENTINELX_AGENT_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Set SENTINELX_AGENT_TOKEN in this PowerShell process before starting the monitor."
}
$uri = [Uri]$apiBase
if ($uri.Scheme -ne "http" -or $uri.Host -notin @("127.0.0.1", "localhost", "::1")) {
    throw "The local event agent only supports HTTP loopback SentinelX URLs."
}

$lastEventTime = (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes)
$lastRecordId = 0L
Write-Host "SentinelX Windows Security log monitor is running. Press Ctrl+C to stop."
Write-Host "Reading Security events 4624/4625 only; raw event XML is not uploaded."
while ($true) {
    try {
        $windowsEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            Id = @(4624, 4625)
            StartTime = $lastEventTime.ToLocalTime()
        } -MaxEvents 5000 -Oldest
    }
    catch {
        if ($_.FullyQualifiedErrorId -like "*NoMatchingEventsFound*") {
            $windowsEvents = @()
        }
        else {
            throw
        }
    }

    $records = @(
        foreach ($event in $windowsEvents) {
            if ([long]$event.RecordId -le $lastRecordId) {
                continue
            }
            $xml = [xml]$event.ToXml()
            $fields = @{}
            foreach ($item in $xml.Event.EventData.Data) {
                if ($item.Name) {
                    $fields[[string]$item.Name] = [string]$item.'#text'
                }
            }
            $username = $fields["TargetUserName"]
            if ([string]::IsNullOrWhiteSpace($username)) {
                $username = $fields["SubjectUserName"]
            }
            $sourceIp = $fields["IpAddress"]
            if ($sourceIp -in @("", "-", "::1", "127.0.0.1")) {
                $sourceIp = $null
            }
            $id = [int]$event.Id
            $outcome = if ($id -eq 4625) { "failure" } else { "success" }
            [ordered]@{
                timestamp = $event.TimeCreated.ToUniversalTime().ToString("o")
                event_type = "windows_security_logon_${id}_$outcome"
                outcome = $outcome
                username = $username
                source_ip = $sourceIp
                host_name = $event.MachineName
            }
        }
    )

    if ($records.Count -gt 0) {
        $newEvents = @(
            foreach ($event in $windowsEvents) {
                if ([long]$event.RecordId -gt $lastRecordId) {
                    $event
                }
            }
        )
        for ($offset = 0; $offset -lt $records.Count; $offset += $BatchSize) {
            $end = [Math]::Min($offset + $BatchSize - 1, $records.Count - 1)
            $batch = @($records[$offset..$end])
            $body = ConvertTo-Json -InputObject @{ events = $batch } -Depth 5 -Compress
        $headers = @{ Authorization = "Bearer $token" }
        $response = Invoke-RestMethod -Uri "$apiBase/api/host-monitor/windows-events" `
            -Method Post -Headers $headers -ContentType "application/json" -Body $body
            $lastEvent = $newEvents[$end]
            $lastRecordId = [long]$lastEvent.RecordId
            $lastEventTime = $lastEvent.TimeCreated.ToUniversalTime()
        Write-Host ("{0}: {1} imported, {2} duplicates, {3} rejected." -f `
            (Get-Date -Format "s"), $response.data.records_imported, `
            $response.data.records_duplicate, $response.data.records_rejected)
        }
    }
    else {
        $lastEventTime = (Get-Date).ToUniversalTime()
    }

    Start-Sleep -Seconds $PollSeconds
}
