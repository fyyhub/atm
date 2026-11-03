# 交叉编译 Linux 发布产物（Windows 宿主机用；CGO_ENABLED=0，amd64 + arm64）。
# 用法：powershell -File deploy\build-release.ps1 [版本号]
param([string]$Version = "dev")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
New-Item -ItemType Directory -Force dist | Out-Null
foreach ($t in @(@("linux","amd64"), @("linux","arm64"))) {
  $goos, $goarch = $t[0], $t[1]
  $out = "dist/atomcode2api-$goos-$goarch"
  Write-Host "==> $out (version=$Version)"
  $env:CGO_ENABLED = "0"; $env:GOOS = $goos; $env:GOARCH = $goarch
  go build -ldflags="-s -w" -o $out .
  Remove-Item Env:CGO_ENABLED, Env:GOOS, Env:GOARCH
  tar czf "$out.tar.gz" -C dist "atomcode2api-$goos-$goarch"
}
Write-Host "完成：dist/"
