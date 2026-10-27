import os
import subprocess
import shutil

print("1. Suricata check:")
suricata_cmd = shutil.which('suricata') or shutil.which('suricata.exe')
print("   Suricata in PATH:", suricata_cmd)
paths_to_check = [
    r"C:\Program Files\Suricata",
    r"C:\Program Files (x86)\Suricata",
    r"C:\Suricata",
    os.path.expanduser(r"~\Downloads"),
    r"D:\Suricata",
    r"D:\mkhang"
]
for p in paths_to_check:
    if os.path.exists(p):
        print(f"   Checked path: {p}")
        try:
            files = [f for f in os.listdir(p) if 'suricata' in f.lower()]
            if files:
                print("     Found Suricata files:", files)
        except Exception:
            pass

print("\n2. YARA check:")
yara_cmd = shutil.which('yara') or shutil.which('yara64')
print("   YARA in PATH:", yara_cmd)
try:
    import yara
    print("   Python yara-python: INSTALLED")
except ImportError:
    print("   Python yara-python: NOT installed")

print("\n3. Windows Defender Firewall check:")
try:
    out = subprocess.check_output("netsh advfirewall show currentprofile state", shell=True).decode('cp437', errors='ignore')
    print("   Firewall state:\n  ", out.strip())
except Exception as e:
    print("   Firewall err:", e)
