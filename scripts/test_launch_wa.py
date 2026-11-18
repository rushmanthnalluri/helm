import subprocess
import time
import sys
sys.path.insert(0, r'd:\homie')
import windows_tools

print("Attempting to launch WhatsApp via start whatsapp: ...")
subprocess.run("cmd.exe /c start whatsapp:", shell=True)
time.sleep(2.0)

wins = windows_tools.find_windows('whatsapp')
print("Wins after start whatsapp:", wins)

if not wins:
    print("Trying explorer shell:AppsFolder...")
    # Find full AUMID
    res = subprocess.run('powershell -Command "(Get-StartApps | Where-Object { $_.Name -like \'*whatsapp*\' }).AppID"', capture_output=True, text=True, shell=True)
    aumid = res.stdout.strip()
    print("AUMID:", aumid)
    if aumid:
        subprocess.run(f'explorer.exe "shell:AppsFolder\\{aumid}"', shell=True)
        time.sleep(2.0)
        wins = windows_tools.find_windows('whatsapp')
        print("Wins after explorer launch:", wins)
