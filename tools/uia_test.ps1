Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class M{[DllImport("user32.dll")]public static extern bool SetForegroundWindow(IntPtr h);[DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr h,int c);[DllImport("user32.dll")]public static extern bool MoveWindow(IntPtr h,int x,int y,int w,int t,bool r);[DllImport("user32.dll")]public static extern void mouse_event(uint f,uint x,uint y,uint d,int e);}' -ErrorAction SilentlyContinue

# 1. Simulate broken state: dead proxy in registry
$e = 'HKCU:\Environment'
foreach ($n in 'http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY','all_proxy') {
    Set-ItemProperty -Path $e -Name $n -Value 'http://10.185.189.184:9000' -Type String
}
$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty $k -Name ProxyEnable -Value 1 -Type DWord
Set-ItemProperty $k -Name ProxyServer -Value 'http=10.185.189.184:9000;https=10.185.189.184:9000' -Type String
Write-Output "=== BEFORE: broken state set ==="
Write-Output "http_proxy = $((Get-ItemProperty $e -Name http_proxy).http_proxy)"
Write-Output "ProxyEnable = $((Get-ItemProperty $k).ProxyEnable)"

# 2. Click the Reset button in the app
$root = [System.Windows.Automation.AutomationElement]::RootElement
$wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
$w = $null
foreach ($x in $wins) { if ($x.Current.Name -like "*TetherLink*") { $w = $x; break } }
if (-not $w) { Write-Output "WINDOW_NOT_FOUND"; exit 1 }

$h = [IntPtr]$w.Current.NativeWindowHandle
[M]::ShowWindow($h, 9) | Out-Null
[M]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 1000

$all = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
$btn = $null
foreach ($e2 in $all) {
    if ($e2.Current.ControlType.ProgrammaticName -match 'Button' -and $e2.Current.Name -match "") { $btn = $e2; break }
}
if (-not $btn) { Write-Output "RESET_BTN_NOT_FOUND"; exit 1 }

try {
    $p = $btn.GetClickablePoint()
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point([int]$p.X, [int]$p.Y)
    Start-Sleep -Milliseconds 400
    [M]::mouse_event(0x0002, 0, 0, 0, 0)
    [M]::mouse_event(0x0004, 0, 0, 0, 0)
    Write-Output "CLICKED reset at $([int]$p.X),$([int]$p.Y)"
} catch {
    Write-Output "CLICK_FAILED: $($_.Exception.Message)"
}

Start-Sleep -Seconds 6

# 3. Verify
Write-Output ""
Write-Output "=== AFTER RESET ==="
$e2 = 'HKCU:\Environment'
foreach ($n in 'http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY','all_proxy') {
    $v = (Get-ItemProperty $e2 -Name $n -ErrorAction SilentlyContinue).$n
    Write-Output "$n = [$v]"
}
$kk = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Write-Output "ProxyEnable = $($kk.ProxyEnable)"
Write-Output "ProxyServer = [$($kk.ProxyServer)]"

# 4. Log from the app
$all2 = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
Write-Output ""
Write-Output "=== APP LOG (last) ==="
$logs = @()
foreach ($e3 in $all2) { if ($e3.Current.Name -match '^\d{2}:\d{2}:\d{2}') { $logs += $e3.Current.Name } }
$logs | Select-Object -Unique | Select-Object -Last 6
