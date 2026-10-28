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

function Get-LocalIndicators([string]$Text) {
    $indicators = [System.Collections.Generic.List[string]]::new()
    if ($Text -match '(?i)(?:-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{20,}={0,2}|FromBase64String|Convert::FromBase64String)') {
        $indicators.Add("encoded_command")
    }
    if ($Text -match '(?is)(?:Invoke-Expression|\biex\b).{0,180}(?:DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|WebClient)') {
        $indicators.Add("download_cradle")
    }
    if ($Text -match '(?i)(?:mimikatz|sekurlsa::|lsadump::|kerberos::)') {
        $indicators.Add("credential_access_signature")
    }
    if ($Text -match '(?i)(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete)') {
        $indicators.Add("shadow_copy_deletion")
    }
    return @($indicators | Select-Object -Unique)
}

$headers = @{ Authorization = "Bearer $token" }
$lastEventTime = (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes)
$lastRecordId = 0L
$windowsEventIds = @(4624, 4625, 5157, 4104, 4688)
Write-Host "SentinelX Windows Security monitor started; raw command lines and script blocks are never uploaded."
Write-Host "Reading Security events 4624, 4625, 5157, 4104, and 4688. Press Ctrl+C to stop."

while ($true) {
    try {
        $windowsEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            Id = $windowsEventIds
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

    $newEvents = @(
        foreach ($event in $windowsEvents) {
            if ([long]$event.RecordId -gt $lastRecordId) {
                $event
            }
        }
    )
    $records = @(
        foreach ($event in $newEvents) {
            $xml = [xml]$event.ToXml()
            $fields = @{}
            foreach ($item in $xml.Event.EventData.Data) {
                if ($item.Name) {
                    $fields[[string]$item.Name] = [string]$item.'#text'
                }
            }
            $id = [int]$event.Id
            $username = $fields["TargetUserName"]
            if ([string]::IsNullOrWhiteSpace($username)) {
                $username = $fields["SubjectUserName"]
            }
            $record = [ordered]@{
                timestamp = $event.TimeCreated.ToUniversalTime().ToString("o")
                event_type = "windows_security_event_$id"
                outcome = "unknown"
                username = $username
                host_name = $event.MachineName
                host_event_record_id = [string]$event.RecordId
            }

            if ($id -eq 4624 -or $id -eq 4625) {
                $record.event_type = if ($id -eq 4625) {
                    "windows_security_logon_4625_failure"
                }
                else {
                    "windows_security_logon_4624_success"
                }
                $record.outcome = if ($id -eq 4625) { "failure" } else { "success" }
                $sourceIp = $fields["IpAddress"]
                if ($sourceIp -notin @("", "-", "::1", "127.0.0.1")) {
                    $record.source_ip = $sourceIp
                }
            }
            elseif ($id -eq 5157) {
                $record.event_type = "windows_firewall_blocked_5157"
                $record.outcome = "failure"
                $sourceIp = $fields["SourceAddress"]
                if ($sourceIp -notin @("", "-", "::1", "127.0.0.1")) {
                    $record.source_ip = $sourceIp
                }
                $port = $fields["DestPort"]
                if ($port -match '^\d{1,5}$' -and [int]$port -ge 1 -and [int]$port -le 65535) {
                    $record.destination_port = [int]$port
                }
            }
            elseif ($id -eq 4104) {
                $record.event_type = "windows_script_block_4104"
                $scriptText = $fields["ScriptBlockText"]
                $tags = @(Get-LocalIndicators $scriptText)
                if ($tags.Count -gt 0) {
                    $record.outcome = "failure"
                    $record.indicator_tags = $tags
                }
            }
            elseif ($id -eq 4688) {
                $record.event_type = "windows_process_creation_4688"
                $processPath = $fields["NewProcessName"]
                $parentPath = $fields["ParentProcessName"]
                $record.process_name = [IO.Path]::GetFileName($processPath)
                $record.parent_process_name = [IO.Path]::GetFileName($parentPath)
                $processId = $fields["NewProcessId"]
                if ($processId -match '^(?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})$') {
                    $record.process_id = $processId
                }
                $tags = @(Get-LocalIndicators $fields["CommandLine"])
                if ($tags.Count -gt 0) {
                    $record.outcome = "failure"
                    $record.indicator_tags = @($tags + "suspicious_process" | Select-Object -Unique)
                }
            }
            $record
        }
    )

    for ($offset = 0; $offset -lt $records.Count; $offset += $BatchSize) {
        $end = [Math]::Min($offset + $BatchSize - 1, $records.Count - 1)
        $batch = @($records[$offset..$end])
        $body = ConvertTo-Json -InputObject @{ events = $batch } -Depth 5 -Compress
        $response = Invoke-RestMethod -Uri "$apiBase/api/host-monitor/windows-events" `
            -Method Post -Headers $headers -ContentType "application/json" -Body $body
        $lastEvent = $newEvents[$end]
        $lastRecordId = [long]$lastEvent.RecordId
        $lastEventTime = $lastEvent.TimeCreated.ToUniversalTime()
        Write-Host ("{0}: {1} imported, {2} duplicates, {3} rejected; {4} detections created." -f `
            (Get-Date -Format "s"), $response.data.records_imported, `
            $response.data.records_duplicate, $response.data.records_rejected, `
            $response.data.detection.alerts_created)
    }

    if ($records.Count -eq 0) {
        $lastEventTime = (Get-Date).ToUniversalTime().AddMinutes(-2)
    }
    Start-Sleep -Seconds $PollSeconds
}
