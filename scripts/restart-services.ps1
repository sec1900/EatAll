# 重启 EatAll 服务（管道 + dashboard），用于代码更新后热加载
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*pipeline/main.py*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 1
Start-Process -FilePath "python" -ArgumentList "pipeline/main.py","run" -WorkingDirectory "E:\EatAll" -WindowStyle Hidden -RedirectStandardOutput "E:\EatAll\data\logs\pipeline.out" -RedirectStandardError "E:\EatAll\data\logs\pipeline.err"
Start-Process -FilePath "python" -ArgumentList "pipeline/main.py","dashboard","--port","9090" -WorkingDirectory "E:\EatAll" -WindowStyle Hidden -RedirectStandardOutput "E:\EatAll\data\logs\dash.out" -RedirectStandardError "E:\EatAll\data\logs\dash.err"
Start-Sleep 4
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*pipeline/main.py*" } | ForEach-Object { "{0} | {1}" -f $_.ProcessId, $_.CommandLine }
