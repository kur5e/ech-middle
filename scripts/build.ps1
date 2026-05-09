# Cross-compile ech-middle for all supported platforms.
# Requires Go 1.23+. Run: .\scripts\build.ps1

param(
    [string]$Target = "",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"
Push-Location "$PSScriptRoot\.."

$env:CGO_ENABLED = "0"
$ldflags = "-s -w"
$Version = if ($env:VERSION) { $env:VERSION } else { "dev" }
$BuildTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss_UTC")
$GitCommit = try { git rev-parse --short HEAD 2>$null } catch { "unknown" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$fullLdflags = "$ldflags -X main.version=$Version -X main.buildTime=$BuildTime -X main.gitCommit=$GitCommit"

$targets = @(
    @{Label="windows_amd64";  Os="windows"; Arch="amd64"}
    @{Label="linux_amd64";    Os="linux";   Arch="amd64"}
    @{Label="linux_arm64";    Os="linux";   Arch="arm64"}
    @{Label="darwin_amd64";   Os="darwin";  Arch="amd64"}
    @{Label="darwin_arm64";   Os="darwin";  Arch="arm64"}
    @{Label="openwrt_mipsle"; Os="linux";   Arch="mipsle"; Mips="softfloat"}
)

function Build-One {
    param($t)

    $outName = "ech-middle_$($t.Label)"
    if ($t.Os -eq "windows") { $outName += ".exe" }

    Write-Host ">>> $($t.Label) ($($t.Os)/$($t.Arch))"

    $env:GOOS = $t.Os
    $env:GOARCH = $t.Arch
    if ($t.Mips) { $env:GOMIPS = $t.Mips }

    go build -ldflags="$fullLdflags" -trimpath -o "$OutDir\$outName" .

    $size = (Get-Item "$OutDir\$outName").Length
    $sizeKB = [math]::Round($size / 1KB)
    Write-Host "    -> $OutDir\$outName  (${sizeKB} KB)"
}

Write-Host "ech-middle cross-compile builder"
Write-Host "Version:    $Version"
Write-Host "Commit:     $GitCommit"
Write-Host "Go version: $(go version)"
Write-Host "Output:     $OutDir"
Write-Host ""

if ($Target) {
    $parts = $Target -split "/"
    $t = @{Label="$($parts[0])_$($parts[1])"; Os=$parts[0]; Arch=$parts[1]}
    if ($t.Os -eq "linux" -and $t.Arch -eq "mipsle") {
        $t.Label = "openwrt_mipsle"
        $t.Mips = "softfloat"
    }
    Build-One -t $t
} else {
    foreach ($t in $targets) { Build-One -t $t }
}

Write-Host ""
Write-Host "Done! Binaries in $OutDir"
Get-ChildItem $OutDir | Select-Object Name, @{Name='SizeKB';Expression={[math]::Round($_.Length/1KB)}}

Pop-Location
