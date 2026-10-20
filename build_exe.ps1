# Build and verify the same console-capable executable used by release CI.
param(
    [string]$Python = "python",
    [switch]$SkipDependencyInstall
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonCommand = Get-Command $Python -ErrorAction Stop
$selectedPython = $pythonCommand.Source
Write-Host "Using Python: $selectedPython"

if (-not $SkipDependencyInstall) {
    & $selectedPython -m pip install --quiet pyinstaller customtkinter pystray Pillow
    if ($LASTEXITCODE -ne 0) { throw "Build dependency installation failed ($LASTEXITCODE)" }
}

$releaseVersion = (Get-Content -LiteralPath (Join-Path $scriptDir "VERSION") -Raw).Trim()
if ($releaseVersion -notmatch '^\d+\.\d+\.\d+$') { throw "VERSION must contain major.minor.patch" }
$versionTuple = (($releaseVersion.Split('.') | ForEach-Object { [int]$_ }) + @(0)) -join ', '
$buildRoot = Join-Path $scriptDir (".saipen\kitchen\exe-build-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $buildRoot -ErrorAction Stop | Out-Null
$distPath = Join-Path $scriptDir "dist"
$entryPoint = Join-Path $scriptDir "_SMART_VAC_CLEANER.py"
$stringsPath = Join-Path $scriptDir "strings"
$versionInfoPath = Join-Path $buildRoot "version-info.txt"
$versionInfo = @"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($versionTuple), prodvers=($versionTuple),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'vacterro'),
    StringStruct('FileDescription', 'Smart VAC Cleaner'),
    StringStruct('FileVersion', '$releaseVersion'),
    StringStruct('InternalName', 'SmartVACCleaner'),
    StringStruct('OriginalFilename', 'SmartVACCleaner.exe'),
    StringStruct('ProductName', 'Smart VAC Cleaner'),
    StringStruct('ProductVersion', '$releaseVersion')
  ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])]
)
"@
[System.IO.File]::WriteAllText($versionInfoPath, $versionInfo, [System.Text.UTF8Encoding]::new($false))

$rootExe = Join-Path $scriptDir "SmartVACCleaner.exe"
if (Test-Path -LiteralPath $rootExe) {
    Copy-Item -LiteralPath $rootExe -Destination (Join-Path $buildRoot "previous-root.exe") -ErrorAction Stop
}

# The unique workspace is already clean. Avoid clearing shared PyInstaller caches.
# Console support preserves CLI stdout; normal GUI startup hides its console.
$pyInstallerArgs = @(
    "-m", "PyInstaller", "--onefile", "--console", "--noconfirm",
    "--name", "SmartVACCleaner", "--collect-data", "customtkinter",
    "--add-data", ($stringsPath + ";strings"), "--version-file", $versionInfoPath,
    "--distpath", $distPath, "--workpath", (Join-Path $buildRoot "work"),
    "--specpath", (Join-Path $buildRoot "spec"), $entryPoint
)
& $selectedPython @pyInstallerArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed ($LASTEXITCODE)" }

$builtExe = Join-Path $distPath "SmartVACCleaner.exe"
if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) { throw "Build produced no executable" }
$builtVersion = (Get-Item -LiteralPath $builtExe).VersionInfo.ProductVersion
if ($builtVersion -ne $releaseVersion) { throw "Executable version mismatch: $builtVersion != $releaseVersion" }

& $selectedPython (Join-Path $scriptDir "test_frozen_exe.py") $builtExe
if ($LASTEXITCODE -ne 0) { throw "Frozen executable verification failed ($LASTEXITCODE)" }

Copy-Item -LiteralPath $builtExe -Destination $rootExe -Force -ErrorAction Stop
Write-Host "Verified SmartVACCleaner.exe v$releaseVersion created in project root and dist."
