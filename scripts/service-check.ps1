# EatAll service check (ASCII only)
$r = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "python.exe" -or $_.Name -eq "eatal-proxy.exe" }
$proxy = @($r | Where-Object { $_.Name -eq "eatal-proxy.exe" }).Count -gt 0
$pipeline = @($r | Where-Object { $_.Name -eq "python.exe" -and $_.CommandLine -like "*main.py run*" }).Count -gt 0
$dash = @($r | Where-Object { $_.Name -eq "python.exe" -and $_.CommandLine -like "*main.py dashboard*" }).Count -gt 0
Write-Output ("proxy=" + $proxy + ";pipeline=" + $pipeline + ";dashboard=" + $dash)
