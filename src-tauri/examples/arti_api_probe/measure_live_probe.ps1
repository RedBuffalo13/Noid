# Bounded live measurement: samples RSS/CPU/TCP-conn of the probe while the
# measure test runs. Requires -AllowNetwork (blanket consent granted
# 2026-11-07: isolated temp state, external watchdog, no Noid data).
param(
    [switch]$AllowNetwork,
    [string]$StateDir = "",
    [string]$OutFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not $AllowNetwork) {
    throw "Live Tor measurement requires -AllowNetwork."
}

Push-Location $PSScriptRoot
try {
    $build = & cargo test --lib --no-run --locked --offline --jobs 1 --message-format=json
    if ($LASTEXITCODE -ne 0) { throw "Offline probe build failed (exit $LASTEXITCODE)." }
    $exe = @(
        foreach ($line in $build) {
            $r = $line | ConvertFrom-Json
            if ($r.reason -eq "compiler-artifact" -and $r.profile.test -and
                $r.executable -and $r.target.name -eq "noid_arti_api_probe") {
                $r.executable
            }
        }
    )
    if ($exe.Count -ne 1) { throw "Expected exactly one probe test executable." }
    Write-Output ("probe_exe_size_bytes={0}" -f (Get-Item $exe[0]).Length)

    $envMap = @{}
    if ($StateDir -ne "") { $envMap["NOID_PROBE_STATE_DIR"] = $StateDir }

    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $exe[0]
    $info.Arguments = "--ignored --exact tests::live_measure_test::live_measure_bootstrap_idle --nocapture --test-threads=1"
    $info.UseShellExecute = $false
    $info.RedirectStandardError = $true
    $info.RedirectStandardOutput = $true
    $info.WorkingDirectory = $PSScriptRoot
    foreach ($k in $envMap.Keys) { $info.EnvironmentVariables[$k] = $envMap[$k] }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $info
    [void]$proc.Start()

    # Incremental, non-blocking log drain: ReadLineAsync completes per line;
    # event handlers are avoided (PS -File mode can fault on async events).
    $errRead = $proc.StandardError.ReadLineAsync()
    $outRead = $proc.StandardOutput.ReadLineAsync()
    function Drain-Log {
        if ($script:errRead.IsCompleted) {
            $l = $script:errRead.Result
            if ($null -ne $l) { Write-Output ("LOG " + $l); $script:errRead = $proc.StandardError.ReadLineAsync() }
        }
        if ($script:outRead.IsCompleted) {
            $l = $script:outRead.Result
            if ($null -ne $l) { Write-Output ("LOG " + $l); $script:outRead = $proc.StandardOutput.ReadLineAsync() }
        }
    }

    $limit = [Diagnostics.Stopwatch]::StartNew()
    $prevCpu = $null
    $prevTime = $null
    $rows = @()
    while (-not $proc.HasExited -and $limit.ElapsedMilliseconds -lt 660000) {
        Start-Sleep -Seconds 5
        Drain-Log
        if ($proc.HasExited) { break }
        $proc.Refresh()
        $conns = 0
        try {
            $conns = @(Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue).Count
        } catch { $conns = -1 }
        $cpuPct = 0.0
        if ($null -ne $prevCpu) {
            $dt = ($proc.TotalProcessorTime - $prevCpu).TotalMilliseconds
            $wall = ($limit.Elapsed - $prevTime).TotalMilliseconds
            if ($wall -gt 0) { $cpuPct = [math]::Round($dt / $wall / [Environment]::ProcessorCount * 100, 2) }
        }
        $prevCpu = $proc.TotalProcessorTime
        $prevTime = $limit.Elapsed
        $row = "t={0}s rss_mb={1} cpu_pct={2} tcp_conns={3}" -f `
            [math]::Round($limit.Elapsed.TotalSeconds), `
            [math]::Round($proc.WorkingSet64 / 1MB, 1), $cpuPct, $conns
        Write-Output $row
        $rows += $row
    }
    Drain-Log
    if (-not $proc.HasExited) {
        $proc.Kill(); $proc.WaitForExit()
        throw "Measurement exceeded external deadline."
    }
    $proc.WaitForExit()
    Start-Sleep -Milliseconds 300
    Drain-Log
    Write-Output ("exit_code={0} total_s={1}" -f $proc.ExitCode, [math]::Round($limit.Elapsed.TotalSeconds))
    if ($proc.ExitCode -ne 0) { throw "Probe exited $($proc.ExitCode)." }
    if ($OutFile -ne "") { $rows | Out-File -Encoding utf8 $OutFile }
} finally {
    Pop-Location
}
