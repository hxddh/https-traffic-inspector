# Installs the latest httpmon release (or $env:HTTPMON_VERSION, e.g. v4.0.0)
# for Windows, verifying its SHA-256 checksum.
#
#   irm https://github.com/hxddh/https-traffic-inspector/releases/latest/download/install.ps1 | iex
#
# Installs to $env:HTTPMON_INSTALL_DIR, else %LOCALAPPDATA%\Programs\httpmon,
# and adds that directory to the user's PATH.
$ErrorActionPreference = 'Stop'

$repo = 'hxddh/https-traffic-inspector'
$version = if ($env:HTTPMON_VERSION) { $env:HTTPMON_VERSION } else { 'latest' }
$dir = if ($env:HTTPMON_INSTALL_DIR) { $env:HTTPMON_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\httpmon' }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'amd64' }
  default { throw "httpmon install: unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
}
$base = if ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$version" }
$asset = "httpmon-windows-$arch.exe"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading $asset ($version)..."
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
  Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

  $want = (Get-Content (Join-Path $tmp 'SHA256SUMS') | Where-Object { ($_ -split '\s+')[1] -eq $asset } | ForEach-Object { ($_ -split '\s+')[0] })
  if (-not $want) { throw "httpmon install: $asset is not listed in SHA256SUMS" }
  $got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
  if ($got -ne $want.ToLower()) { throw "httpmon install: checksum mismatch for $asset (got $got, want $want)" }

  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Move-Item -Force (Join-Path $tmp $asset) (Join-Path $dir 'httpmon.exe')
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
  Write-Host "Added $dir to your PATH; open a new terminal to use it."
}
& (Join-Path $dir 'httpmon.exe') --version
