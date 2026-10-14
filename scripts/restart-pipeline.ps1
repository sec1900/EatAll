# 重启管道 daemon（先杀全部 main.py run，再起单个——多 daemon 会竞争 ingest state）
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*pipeline/main.py run*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
Start-Process -FilePath "python" -ArgumentList "pipeline/main.py","run" -WorkingDirectory "E:\EatAll" -WindowStyle Hidden -RedirectStandardOutput "E:\EatAll\data\logs\pipeline.out" -RedirectStandardError "E:\EatAll\data\logs\pipeline.err"
Start-Sleep 4
$runs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*pipeline/main.py run*" }
"pipeline daemon count: " + @($runs).Count
