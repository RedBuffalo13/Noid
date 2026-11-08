param(
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$ArtiVersion = '0.47.0',
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$SqlxVersion = '0.8.6',
    [switch]$ExpectSqliteConflict
)

$ErrorActionPreference = 'Stop'
$cargo = (Get-Command cargo -CommandType Application).Source
$tempRoot = [System.IO.Path]::GetTempPath()
if (-not [System.IO.Directory]::Exists($tempRoot)) {
    throw 'Temporary directory is unavailable'
}
$probe = Join-Path $tempRoot ("noid-tor-dependencies-" + [guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($probe) | Out-Null
$encoding = New-Object System.Text.UTF8Encoding($false)
$manifest = @"
[package]
name = "noid-tor-dependency-probe"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[[bin]]
name = "probe"
path = "main.rs"

[dependencies]
arti-client = { version = "=$ArtiVersion", default-features = false, features = ["tokio", "rustls", "onion-service-client", "onion-service-service"] }
sqlx = { version = "=$SqlxVersion", default-features = false, features = ["runtime-tokio", "sqlite", "macros", "chrono", "migrate"] }
"@
[System.IO.File]::WriteAllText((Join-Path $probe 'Cargo.toml'), $manifest, $encoding)
[System.IO.File]::WriteAllText((Join-Path $probe 'main.rs'), "fn main() {}`n", $encoding)
$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = $cargo
$start.Arguments = 'metadata --format-version 1'
$start.WorkingDirectory = $probe
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = New-Object System.Diagnostics.Process
$process.StartInfo = $start
if (-not $process.Start()) {
    throw 'Unable to start Cargo'
}
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$process.WaitForExit()
$output = $stdout.GetAwaiter().GetResult()
$diagnostics = $stderr.GetAwaiter().GetResult()
$exitCode = $process.ExitCode
$process.Dispose()
[System.IO.File]::WriteAllText((Join-Path $probe 'metadata.json'), $output, $encoding)
[System.IO.File]::WriteAllText((Join-Path $probe 'cargo.stderr.txt'), $diagnostics, $encoding)
$sqliteConflict = $exitCode -ne 0 -and
    $diagnostics.Contains('libsqlite3-sys') -and
    $diagnostics.Contains('links') -and
    $diagnostics.Contains('sqlite3')
if ($exitCode -eq 0) {
    $node = (Get-Command node -CommandType Application).Source
    $parserPath = Join-Path $probe 'sqlite_versions.cjs'
    $parser = @'
const fs = require("node:fs");
const metadata = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
for (const p of metadata.packages) {
    if (p.name === "libsqlite3-sys") console.log(p.version);
}
'@
    [System.IO.File]::WriteAllText($parserPath, $parser, $encoding)
    $sqliteVersions = @(& $node $parserPath (Join-Path $probe 'metadata.json'))
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to parse resolved metadata; inspect $probe"
    }
} else {
    $sqliteVersions = @()
}
[ordered]@{
    arti = $ArtiVersion
    sqlx = $SqlxVersion
    cargo_exit_code = $exitCode
    sqlite_links_conflict = $sqliteConflict
    resolved_sqlite_versions = $sqliteVersions
    evidence_directory = $probe
} | ConvertTo-Json
if ($ExpectSqliteConflict) {
    if (-not $sqliteConflict) {
        throw "Expected SQLite links conflict was not reproduced; inspect $probe"
    }
} elseif ($exitCode -ne 0) {
    throw "Dependency resolution failed; inspect $probe"
}
