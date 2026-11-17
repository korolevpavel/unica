# Run only on the separately assigned Windows x64 build host/slot.
param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference = 'Stop'
$head = '9ccfa8f6f92248366df079733718db8f870ea754'
if (Test-Path -LiteralPath $Root) { throw 'Root must not exist; use a new isolated directory.' }
New-Item -ItemType Directory -Path $Root | Out-Null
$Root = (Resolve-Path -LiteralPath $Root).Path
function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed: $LASTEXITCODE" }
}
$env:CARGO_PROFILE_DEV_DEBUG = 'line-tables-only'
$env:PYTHONUTF8 = '1'
$env:CARGO_TARGET_DIR = Join-Path $Root 'candidate-target'
Invoke-Native 'git' @('clone', '--depth', '1', '--no-checkout', 'https://github.com/IngvarConsulting/unica.git', (Join-Path $Root 'candidate'))
$candidate = Join-Path $Root 'candidate'
Invoke-Native 'git' @('-C', $candidate, 'fetch', '--depth', '1', 'origin', 'refs/pull/2355/head')
$live = (& git -C $candidate rev-parse FETCH_HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $live -ne $head) { throw 'PR head changed; stop and re-check compatibility.' }
Invoke-Native 'git' @('-C', $candidate, 'checkout', '--detach', $head)
# Only bootstrap is built; core and engines retain the original published pins.
Push-Location -LiteralPath $candidate
try {
    $ErrorActionPreference = 'Continue'
    & cargo build --locked --release --target x86_64-pc-windows-msvc -p unica-bootstrap --bin unica-bootstrap 2>&1 |
        Tee-Object -FilePath (Join-Path $Root 'candidate-build.log')
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed: $LASTEXITCODE" }
} finally { $ErrorActionPreference = 'Stop'; Pop-Location }
$binary = Join-Path $env:CARGO_TARGET_DIR 'x86_64-pc-windows-msvc/release/unica-bootstrap.exe'
$version = (& $binary --version).Trim()
if ($LASTEXITCODE -ne 0 -or $version -ne 'unica-bootstrap 0.15.0-rc.1') { throw 'Unexpected bootstrap version.' }
@{
    head = $head
    sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    binary = $binary
    version = $version
    rustc = ((& rustc -Vv) -join "`n")
    cargo = ((& cargo -V) -join "`n")
    command = 'cargo build --locked --release --target x86_64-pc-windows-msvc -p unica-bootstrap --bin unica-bootstrap'
    targetDirectory = $env:CARGO_TARGET_DIR
    builtUtc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Root 'candidate-build.json') -Encoding UTF8
Invoke-Native 'git' @('clone', '--depth', '1', '--branch', 'v0.15.0-rc.1', 'https://github.com/IngvarConsulting/unica-marketplace.git', (Join-Path $Root 'marketplace'))
Invoke-Native 'git' @('-C', (Join-Path $Root 'marketplace'), 'rev-parse', 'HEAD') |
    Set-Content -LiteralPath (Join-Path $Root 'marketplace-commit.txt') -Encoding UTF8
Write-Output "Prepared candidate and stock package under $Root. Smoke has NOT run."
