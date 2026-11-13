param(
    [switch]$Offline,
    [switch]$LowMemory,
    [ValidateSet('arm64', 'x86_64')]
    [string]$Architecture = 'arm64'
)

# Release sibling of build_android_arm64.ps1: builds the release cdylib,
# packages assemble<Abi>Release (rustBuild skipped — the .so above is fresh),
# zipaligns and signs with the debug keystore (no release keystore exists —
# see ANDROID_BUILD.md; this is a debug-signed release, NOT Play-grade).
# Never installs the APK or touches application data.
$ErrorActionPreference = 'Stop'
$tauriRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = Split-Path $tauriRoot -Parent
$androidRoot = Join-Path $tauriRoot 'gen\android'
$target = if ($Architecture -eq 'arm64') { 'aarch64-linux-android' } else { 'x86_64-linux-android' }
$abi = if ($Architecture -eq 'arm64') { 'arm64-v8a' } else { 'x86_64' }
$flavor = if ($Architecture -eq 'arm64') { 'Arm64' } else { 'X86_64' }
$targetEnv = $target.Replace('-', '_')
$config = Get-Content -LiteralPath (Join-Path $tauriRoot 'tauri.conf.json') -Raw | ConvertFrom-Json
$sdk = $env:ANDROID_HOME
if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
$ndkRoot = Join-Path $sdk 'ndk\29.0.14206865'
$ndkBin = Join-Path $ndkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$javaHome = $env:JAVA_HOME
if (-not $javaHome) { $javaHome = 'C:\Program Files\Android\Android Studio\jbr' }
$kotlinDir = Join-Path $androidRoot 'app\src\main\java\com\bst\noid\generated'
$jniRoot = Join-Path $androidRoot 'app\src\main\jniLibs'
$jniDir = Join-Path $jniRoot $abi
$gradle = Join-Path $androidRoot 'gradlew.bat'
foreach ($path in @($androidRoot, $ndkBin, $javaHome, $kotlinDir, $jniRoot, $gradle)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required build path is missing: $path" }
}
if (-not (Test-Path -LiteralPath $jniDir)) {
    New-Item -ItemType Directory -Path $jniDir | Out-Null
}

$settings = @{
    JAVA_HOME = $javaHome
    ANDROID_HOME = $sdk
    ANDROID_NDK_HOME = $ndkRoot
    PATH = "$ndkBin;$env:PATH"
    TAURI_ANDROID_PROJECT_PATH = $androidRoot
    TAURI_ANDROID_PACKAGE_UNESCAPED = 'com.bst.noid'
    WRY_ANDROID_PACKAGE = 'com.bst.noid'
    WRY_ANDROID_LIBRARY = 'noid_lib'
    WRY_ANDROID_KOTLIN_FILES_OUT_DIR = $kotlinDir
}
$settings["CC_$targetEnv"] = Join-Path $ndkBin "${target}24-clang.cmd"
$settings["CXX_$targetEnv"] = Join-Path $ndkBin "${target}24-clang++.cmd"
$settings["AR_$targetEnv"] = Join-Path $ndkBin 'llvm-ar.exe'
$settings["CARGO_TARGET_$($targetEnv.ToUpperInvariant())_LINKER"] = $settings["CC_$targetEnv"]
$previous = @{}
foreach ($key in $settings.Keys) {
    $previous[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
    [Environment]::SetEnvironmentVariable($key, $settings[$key], 'Process')
}

Push-Location $repoRoot
try {
    $cargoArgs = @('rustc', '--locked', '--release', '--lib', '--crate-type', 'cdylib', '--jobs', '1', '--target', $target,
        '--manifest-path', (Join-Path $tauriRoot 'Cargo.toml'))
    if ($Offline) { $cargoArgs += '--offline' }
    if ($LowMemory) {
        $cargoArgs += @('--config', 'profile.release.package.noid.debug=0',
            '--config', 'profile.release.package.noid.codegen-units=4',
            '--config', 'profile.release.package.noid.incremental=false')
    }
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { throw "Android release native build failed: $LASTEXITCODE" }

    $metadata = & cargo metadata --no-deps --locked --offline --format-version 1 --manifest-path (Join-Path $tauriRoot 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw 'Unable to resolve Cargo output directory' }
    $targetRoot = ($metadata | ConvertFrom-Json).target_directory
    $library = Join-Path $targetRoot "$target\release\libnoid_lib.so"
    $exports = & (Join-Path $ndkBin 'llvm-nm.exe') --dynamic --defined-only $library
    if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect Android native exports' }
    foreach ($symbol in @('Java_com_bst_noid_Rust_onCreate', 'Java_com_bst_noid_Rust_onStart')) {
        if (-not ($exports -match "\s$symbol$")) {
            throw "Android native library is missing $symbol; check tauri::mobile_entry_point on run()"
        }
    }
    $nativeHash = (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash
    $staged = Join-Path $jniDir 'libnoid_lib.so'
    if ((Test-Path -LiteralPath $staged) -and
        ((Get-Item -LiteralPath $staged).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Native staging path is a link; refusing to overwrite its target: $staged"
    }
    Copy-Item -LiteralPath $library -Destination $staged
    Push-Location $androidRoot
    try {
        $gradleArgs = @(":app:assemble${flavor}Release", '-x', ":app:rustBuild${flavor}Release",
            '--console=plain', "-Ptauri.android.versionName=$($config.version)")
        if ($Offline) { $gradleArgs += '--offline' }
        & $gradle @gradleArgs
        if ($LASTEXITCODE -ne 0) { throw "Android release packaging failed: $LASTEXITCODE" }
    } finally {
        Pop-Location
    }

    $apk = Join-Path $androidRoot "app\build\outputs\apk\$Architecture\release\app-$Architecture-release-unsigned.apk"
    if (-not (Test-Path -LiteralPath $apk)) {
        # AGP may name it without the -unsigned suffix when no signingConfig exists.
        $apk = Join-Path $androidRoot "app\build\outputs\apk\$Architecture\release\app-$Architecture-release.apk"
    }
    if (-not (Test-Path -LiteralPath $apk)) { throw "Release APK not found under $androidRoot\app\build\outputs\apk\$Architecture\release" }

    # zipalign + sign with the debug keystore (documented pipeline, ANDROID_BUILD.md).
    $buildTools = Get-ChildItem -LiteralPath (Join-Path $sdk 'build-tools') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    $zipalign = Join-Path $buildTools.FullName 'zipalign.exe'
    $apksigner = Join-Path $buildTools.FullName 'apksigner.bat'
    $keystore = Join-Path $env:USERPROFILE '.android\debug.keystore'
    $aligned = Join-Path $env:TEMP "noid-$Architecture-release-aligned.apk"
    $signed = Join-Path $env:TEMP "noid-$Architecture-release-signed.apk"
    & $zipalign -f -p 4 $apk $aligned
    if ($LASTEXITCODE -ne 0) { throw "zipalign failed: $LASTEXITCODE" }
    & $apksigner sign --ks $keystore --ks-pass pass:android --key-pass pass:android --out $signed $aligned
    if ($LASTEXITCODE -ne 0) { throw "apksigner failed: $LASTEXITCODE" }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($signed)
    try {
        $entry = $zip.GetEntry("lib/$abi/libnoid_lib.so")
        if (-not $entry) { throw "APK is missing the $abi native library" }
        $stream = $entry.Open()
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $packedHash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '')
        } finally {
            $sha.Dispose()
            $stream.Dispose()
        }
        if ($packedHash -ne $nativeHash) { throw 'APK contains a stale or modified native library' }
    } finally {
        $zip.Dispose()
    }
    [ordered]@{
        apk = $signed
        apk_sha256 = (Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash
        native_sha256 = $nativeHash
        packaged_native_matches = $true
        signed_with = 'debug.keystore'
        installed_on_device = $false
    } | ConvertTo-Json
} finally {
    Pop-Location
}
