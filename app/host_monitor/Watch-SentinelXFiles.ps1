[CmdletBinding()]
param(
    [ValidateRange(10, 300)]
    [int]$PollSeconds = 30,
    [ValidateRange(1, 50)]
    [int]$MaximumFilesPerPoll = 10
)

$ErrorActionPreference = "Stop"
$apiBase = if ($env:SENTINELX_API_BASE) { $env:SENTINELX_API_BASE.TrimEnd("/") } else { "http://127.0.0.1:5000" }
$token = $env:SENTINELX_AGENT_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Set SENTINELX_AGENT_TOKEN in this PowerShell process before starting the file monitor."
}
$uri = [Uri]$apiBase
if ($uri.Scheme -ne "http" -or $uri.Host -notin @("127.0.0.1", "localhost", "::1")) {
    throw "The local file monitor only supports HTTP loopback SentinelX URLs."
}

$headers = @{ Authorization = "Bearer $token" }
$extensions = @(".exe", ".dll", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr")
$seenHashes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$directories = @(
    (Join-Path $env:USERPROFILE "Downloads"),
    $env:TEMP,
    (Join-Path $env:LOCALAPPDATA "Temp")
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Select-Object -Unique

Write-Host "SentinelX file-hash monitor started. Files are hashed locally; contents are never uploaded."
Write-Host "VirusTotal receives hashes only when SENTINELX_ENABLE_FILE_HASH_LOOKUPS=1 is enabled on the server."
while ($true) {
    $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-10)
    $processed = 0
    foreach ($directory in $directories) {
        foreach ($file in (Get-ChildItem -LiteralPath $directory -File -ErrorAction Stop | Where-Object {
            $_.Extension.ToLowerInvariant() -in $extensions -and
            $_.Length -le 104857600 -and
            $_.LastWriteTimeUtc -ge $cutoff
        })) {
            if ($processed -ge $MaximumFilesPerPoll) {
                break
            }
            try {
                $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                if ($seenHashes.Contains($hash)) {
                    continue
                }
                $response = Invoke-RestMethod -Uri "$apiBase/api/host-monitor/file-hash" `
                    -Method Post -Headers $headers -ContentType "application/json" `
                    -Body (ConvertTo-Json -Compress @{ sha256 = $hash; file_path = $file.FullName })
                [void]$seenHashes.Add($hash)
                $processed++
                Write-Host ("{0}: checked SHA-256 {1}; score {2}, suspicious={3}." -f `
                    (Get-Date -Format "s"), $hash, $response.data.score, $response.data.suspicious)
                if ($response.data.local_path_recorded) {
                    Write-Warning "SentinelX stored this suspicious file's local path for human-approved quarantine."
                }
            }
            catch {
                Write-Warning ("File-hash lookup was not completed for a candidate in {0}: {1}" -f $directory, $_.Exception.Message)
            }
        }
        if ($processed -ge $MaximumFilesPerPoll) {
            break
        }
    }
    Start-Sleep -Seconds $PollSeconds
}
