Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class M{[DllImport("user32.dll")]public static extern bool SetForegroundWindow(IntPtr h);[DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr h,int c);[DllImport("user32.dll")]public static extern bool MoveWindow(IntPtr h,int x,int y,int w,int t,bool r);}' -ErrorAction SilentlyContinue

$root = [System.Windows.Automation.AutomationElement]::RootElement
$wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
$w = $null
foreach ($x in $wins) { if ($x.Current.Name -like "*TetherLink*" -or $x.Current.Name -like "*ProxyBridge*") { $w = $x; break } }
if (-not $w) { Write-Output "WINDOW_NOT_FOUND"; exit 1 }

$h = [IntPtr]$w.Current.NativeWindowHandle
[M]::ShowWindow($h, 9) | Out-Null
[M]::MoveWindow($h, 120, 40, 660, 940, $true) | Out-Null
[M]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 1200

function Shot($name) {
    $bmp = New-Object System.Drawing.Bitmap 660, 940
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen(120, 40, 0, 0, $bmp.Size)
    $g.Dispose()
    $bmp.Save("C:\dev\ProxyBridge\tools\$name.png")
}

$a = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
Write-Output "=== TEXTS ==="
foreach ($e in $a) { if ($e.Current.Name) { Write-Output $e.Current.Name } }
Shot "final"
