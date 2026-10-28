[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(5, 2147483647)]
    [int]$ProcessId,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]{1,255}$')]
    [string]$ExpectedName,
    [Parameter(Mandatory = $true)]
    [DateTime]$ObservedAt
)

$ErrorActionPreference = "Stop"
$protectedNames = @(
    "csrss", "lsass", "services", "smss", "system", "system idle process",
    "wininit", "winlogon", "svchost", "registry", "secure system"
)

if ($ExpectedName -match '\.exe$') {
    $expectedBaseName = [IO.Path]::GetFileNameWithoutExtension($ExpectedName)
}
else {
    $expectedBaseName = $ExpectedName
}
if ($protectedNames -contains $expectedBaseName.ToLowerInvariant()) {
    throw "Termination of a protected Windows process is prohibited."
}

$process = Get-Process -Id $ProcessId -ErrorAction Stop
if (-not [string]::Equals($process.ProcessName, $expectedBaseName, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The live process name does not match the evidence; no process was terminated."
}
if ($process.StartTime.ToUniversalTime() -gt $ObservedAt.ToUniversalTime().AddSeconds(30)) {
    throw "The PID appears to have been reused after the evidence event; no process was terminated."
}

Stop-Process -Id $ProcessId -Force -ErrorAction Stop
