# Requires explicit network consent; builds offline, then bounds the test process.
param(
    [ValidateSet("bootstrap", "onion_stream")]
    [string]$Test = "onion_stream",
    [switch]$AllowNetwork
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not $AllowNetwork) {
    throw "Live Tor networking/publication requires explicit -AllowNetwork consent."
}

Push-Location $PSScriptRoot
try {
    $output = & cargo test --lib --no-run --locked --offline --jobs 1 --message-format=json
    if ($LASTEXITCODE -ne 0) {
        throw "Offline probe build failed (exit $LASTEXITCODE)."
    }
    $executables = @(
        foreach ($line in $output) {
            $record = $line | ConvertFrom-Json
            if ($record.reason -eq "compiler-artifact" -and
                $record.profile.test -and $record.executable -and
                $record.target.name -eq "noid_arti_api_probe") {
                $record.executable
            }
        }
    )
    if ($executables.Count -ne 1) {
        throw "Expected exactly one probe test executable."
    }

    $filter = "tests::live_onion_stream_test::live_onion_stream_bidirectional"
    $limitMs = 660000
    if ($Test -eq "bootstrap") {
        $filter = "tests::live_bootstrap_test::live_bootstrap_service_and_shutdown"
        $limitMs = 240000
    }
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $executables[0]
    $info.Arguments = "--ignored --exact $filter --nocapture --test-threads=1"
    $info.UseShellExecute = $false
    $info.WorkingDirectory = $PSScriptRoot
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        if (-not $process.WaitForExit($limitMs)) {
            $process.Kill()
            $process.WaitForExit()
            throw "Live probe exceeded external process deadline."
        }
        if ($process.ExitCode -ne 0) {
            throw "Live probe failed (exit $($process.ExitCode))."
        }
    } finally {
        $process.Dispose()
    }
} finally {
    Pop-Location
}
