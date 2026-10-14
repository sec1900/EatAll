# EatAll proxy restart (ASCII only)
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "eatal-proxy.exe" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
Start-Process -FilePath "E:\EatAll\bin\eatal-proxy.exe" -ArgumentList "-config","config/config.broad.yaml" -WorkingDirectory "E:\EatAll" -WindowStyle Hidden -RedirectStandardOutput "E:\EatAll\data\logs\stdout.log" -RedirectStandardError "E:\EatAll\data\logs\stderr.log"
Start-Sleep 5
$count = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "eatal-proxy.exe" }).Count
Write-Output ("proxy_count=" + $count)
