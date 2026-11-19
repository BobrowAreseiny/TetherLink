# build.ps1 - BUILD ONLY. Does not install anything, does not touch adb,
# so the hotspot and internet through the phone stay alive.

$ErrorActionPreference = 'Stop'
Set-Location 'C:\dev\ProxyBridge'

Write-Host '== 1. Freeing files from previous processes ==' -ForegroundColor Cyan
Get-Process ProxyBridge.Windows -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process VBCSCompiler, MSBuild, dotnet -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

Write-Host '== 2. Windows Release -> artifacts\win-release-new ==' -ForegroundColor Cyan
# PublishReadyToRun=false: crossgen kept files busy in obj\...\R2R and failed
# with "The process cannot access the file ... being used by another process"
Remove-Item -Recurse -Force 'artifacts\win-release-new' -ErrorAction SilentlyContinue
dotnet publish ProxyBridge.Windows -c Release -r win-x64 --self-contained -p:PublishReadyToRun=false -o 'artifacts\win-release-new'
if ($LASTEXITCODE -ne 0) { throw "Windows build failed (exit $LASTEXITCODE)" }

Write-Host '== 3. Android Release APK (full rebuild) ==' -ForegroundColor Cyan
# Clean obj\bin, otherwise incremental build hits
# error XAGNM7009: missing native code generation state for architecture 'Arm64'
Remove-Item -Recurse -Force 'ProxyBridge.Android\obj', 'ProxyBridge.Android\bin' -ErrorAction SilentlyContinue
dotnet build ProxyBridge.Android -c Release -f net10.0-android
if ($LASTEXITCODE -ne 0) { throw "Android build failed (exit $LASTEXITCODE)" }

Write-Host '== 4. Copy APK into artifacts\android-release ==' -ForegroundColor Cyan
New-Item -ItemType Directory -Force 'artifacts\android-release' | Out-Null
Copy-Item 'ProxyBridge.Android\bin\Release\net10.0-android\com.example.proxybridge-Signed.apk' 'artifacts\android-release\ProxyBridge-release.apk' -Force

Write-Host ''
Write-Host 'DONE. Nothing installed - install manually.' -ForegroundColor Green
foreach ($f in @('artifacts\android-release\ProxyBridge-release.apk', 'artifacts\win-release-new\ProxyBridge.Windows.exe')) {
    if (Test-Path $f) {
        $i = Get-Item $f
        Write-Host ("  {0}  {1} MB  {2}" -f $i.FullName, [math]::Round($i.Length / 1MB, 1), $i.LastWriteTime)
    }
    else {
        Write-Host ("  MISSING: {0}" -f $f) -ForegroundColor Red
    }
}
