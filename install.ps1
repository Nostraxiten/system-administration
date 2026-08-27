# system-administration installer for Windows Server and Windows.
#
#   irm https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.ps1 | iex
#
# Puts a single executable named `system-administration.exe` on PATH. A published
# release binary is used when one matches this machine; otherwise the source is
# compiled, installing Rust first if it is missing.
#
# Because `iex` cannot forward parameters, options are environment variables:
#   $env:SYSADM_INSTALL_DIR = 'C:\tools'   where to place the executable
#   $env:SYSADM_VERSION     = 'v1.0.0'     release tag (default: latest)
#   $env:SYSADM_FROM_SOURCE = '1'          always compile, never download

$ErrorActionPreference = 'Stop'

$Repo   = if ($env:SYSADM_REPO) { $env:SYSADM_REPO } else { 'Nostraxiten/system-administration' }
$Branch = if ($env:SYSADM_BRANCH) { $env:SYSADM_BRANCH } else { 'main' }
$Bin    = 'system-administration'
$Exe    = "$Bin.exe"

$Version    = if ($env:SYSADM_VERSION) { $env:SYSADM_VERSION } else { 'latest' }
$FromSource = ($env:SYSADM_FROM_SOURCE -and $env:SYSADM_FROM_SOURCE -ne '0')

function Say  { param([string]$Message) Write-Host "  $Message" }
function Warn { param([string]$Message) Write-Host "  ! $Message" -ForegroundColor Yellow }
function Die  { param([string]$Message) Write-Host ""; Write-Host "  Error: $Message" -ForegroundColor Red; Write-Host ""; exit 1 }

# Windows PowerShell 5 defaults to TLS 1.0, which GitHub refuses.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

function Get-Target {
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    switch ($arch) {
        'AMD64' { return 'x86_64-pc-windows-msvc' }
        'ARM64' { return 'aarch64-pc-windows-msvc' }
        default { return $null }
    }
}

function Get-InstallDir {
    if ($env:SYSADM_INSTALL_DIR) { return $env:SYSADM_INSTALL_DIR }
    return (Join-Path $env:LOCALAPPDATA "Programs\$Bin")
}

function Install-Binary {
    param([string]$SourcePath, [string]$InstallDir)

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    $destination = Join-Path $InstallDir $Exe

    # A running copy cannot be overwritten; move it aside and let Windows
    # reclaim it on the next reboot.
    if (Test-Path $destination) {
        try { Remove-Item $destination -Force } catch {
            Move-Item $destination "$destination.old" -Force -ErrorAction SilentlyContinue
        }
    }
    Copy-Item $SourcePath $destination -Force
    return $destination
}

function Add-ToUserPath {
    param([string]$Directory)

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }

    $entries = $userPath -split ';' | Where-Object { $_ -ne '' }
    foreach ($entry in $entries) {
        if ($entry.TrimEnd('\') -ieq $Directory.TrimEnd('\')) { return $false }
    }

    $updated = if ($userPath -eq '') { $Directory } else { "$userPath;$Directory" }
    [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    $env:Path = "$env:Path;$Directory"
    return $true
}

function Get-Release {
    param([string]$Target, [string]$WorkDir, [string]$InstallDir)

    if (-not $Target) { return $null }

    $asset = "$Bin-$Target.zip"
    $url = if ($Version -eq 'latest') {
        "https://github.com/$Repo/releases/latest/download/$asset"
    } else {
        "https://github.com/$Repo/releases/download/$Version/$asset"
    }

    Say "Looking for a published binary for $Target..."
    $archive = Join-Path $WorkDir $asset
    try {
        Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
    } catch {
        return $null
    }

    $extracted = Join-Path $WorkDir 'release'
    try {
        Expand-Archive -Path $archive -DestinationPath $extracted -Force
    } catch {
        return $null
    }

    $binary = Get-ChildItem -Path $extracted -Filter $Exe -Recurse |
              Select-Object -First 1
    if (-not $binary) { return $null }

    Say "Downloaded the published binary."
    return (Install-Binary -SourcePath $binary.FullName -InstallDir $InstallDir)
}

function Install-Rust {
    param([string]$WorkDir)

    if (Get-Command cargo -ErrorAction SilentlyContinue) { return }

    Say "Rust is not installed; installing rustup non-interactively..."
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }
    $installer = Join-Path $WorkDir 'rustup-init.exe'
    Invoke-WebRequest -Uri "https://win.rustup.rs/$arch" -OutFile $installer -UseBasicParsing

    $process = Start-Process -FilePath $installer `
                             -ArgumentList '-y', '--profile', 'minimal', '--no-modify-path' `
                             -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) { Die "the rustup installation failed." }

    # Use it in this session without depending on a shell restart.
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
    $env:Path = (Join-Path $cargoHome 'bin') + ";$env:Path"

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Die "cargo is still unavailable after installing rustup."
    }
}

function Build-FromSource {
    param([string]$WorkDir, [string]$InstallDir)

    Say "Building from source. This takes a couple of minutes..."
    Install-Rust -WorkDir $WorkDir

    $ref = if ($Version -eq 'latest') { $Branch } else { $Version }
    $archive = Join-Path $WorkDir 'source.zip'
    Invoke-WebRequest -Uri "https://github.com/$Repo/archive/$ref.zip" `
                      -OutFile $archive -UseBasicParsing

    $extracted = Join-Path $WorkDir 'source'
    Expand-Archive -Path $archive -DestinationPath $extracted -Force

    $root = Get-ChildItem -Path $extracted -Directory | Select-Object -First 1
    if (-not $root) { Die "the downloaded source is empty." }

    Push-Location $root.FullName
    try {
        & cargo build --release | Out-Host
        if ($LASTEXITCODE -ne 0) { Die "the build failed." }
    } finally {
        Pop-Location
    }

    $built = Join-Path $root.FullName "target\release\$Exe"
    if (-not (Test-Path $built)) { Die "no executable was produced." }

    return (Install-Binary -SourcePath $built -InstallDir $InstallDir)
}

# ------------------------------------------------------------------- main ----

Write-Host ""
Write-Host "  system-administration installer"
Write-Host ""

$target     = Get-Target
$installDir = Get-InstallDir
$workDir    = Join-Path ([IO.Path]::GetTempPath()) ("sysadm-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
    $installed = $null
    if (-not $FromSource) {
        $installed = Get-Release -Target $target -WorkDir $workDir -InstallDir $installDir
        if (-not $installed) { Say "No published binary for this platform." }
    }
    if (-not $installed) {
        $installed = Build-FromSource -WorkDir $workDir -InstallDir $installDir
    }

    # The tool takes no flags and starts an interactive scan when executed, so
    # the installation is verified by inspecting the file, never by running it.
    if (-not (Test-Path $installed)) { Die "the installation left no executable in $installDir." }

    Write-Host ""
    Say "Installed at $installed"

    if (Add-ToUserPath -Directory $installDir) {
        Say "$installDir was added to your user PATH."
        Warn "Open a new terminal for the PATH change to take effect."
    }
    Say "Then run it by typing:  $Bin"
    Write-Host ""
} finally {
    Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
