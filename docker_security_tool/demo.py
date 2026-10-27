# -*- coding: utf-8 -*-
import os
import sys
import time
import subprocess
import webbrowser

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_SCRIPT = os.path.join(TOOL_DIR, "docker_security_scanner.py")
DEMO_DIR = os.path.join(TOOL_DIR, "demo")
VULN_FILE = os.path.join(DEMO_DIR, "container_inspect_vulnerable.json")
HARDENED_FILE = os.path.join(DEMO_DIR, "container_inspect_hardened.json")
REPORT_HTML = os.path.join(TOOL_DIR, "docker_security_report.html")

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def run_cmd(args):
    return subprocess.run([sys.executable, SCANNER_SCRIPT] + args, cwd=TOOL_DIR)

def menu():
    while True:
        clear()
        print("=" * 80)
        print("     DEMO: CONG CU KIEM TRA CAU HINH VA PHAT HIEN RUI RO DOCKER")
        print("     Mon hoc: Lap trinh An ninh Thong tin - Nhom Sinh vien")
        print("=" * 80)
        print("")
        print("  [1] QUET CONTAINER DINH LOI (Phat hien 8 vi pham + Diem 0/100 + Chan CI/CD)")
        print("  [2] MO GIAO DIEN BAO CAO TRUC QUAN (Dashboard HTML tren Trinh duyet)")
        print("  [3] QUET CONTAINER DA HARDENED (Dat chuan 100/100 + Pass Security Gate)")
        print("  [4] CHAY KICH BAN TU DONG DE QUAY VIDEO (Quet loi -> Mo Web -> Quet Pass)")
        print("  [5] Thoat")
        print("")
        print("=" * 80)
        choice = input("Nhap lua chon cua ban (1-5): ").strip()

        if choice == "1":
            clear()
            print("[DEMO 1] Dang quet Container chua cac cau hinh nguy hiem (Slide 4 - 9)...\n")
            run_cmd([VULN_FILE, "--ci", "--open-browser"])
            print("\n[Luu y]: Ban vua thay cong cu phat hien 8 vi pham va kich hoat Security Gate FAILED.")
            input("\nNhan Enter de quay ve Menu...")
        elif choice == "2":
            clear()
            print("Dang mo giao dien bao cao HTML...")
            if os.path.exists(REPORT_HTML):
                webbrowser.open("file://" + os.path.abspath(REPORT_HTML))
                print("Da mo bao cao tren trinh duyet!")
            else:
                print("Chua co file bao cao. Vui long chay quet truoc!")
            input("\nNhan Enter de quay ve Menu...")
        elif choice == "3":
            clear()
            print("[DEMO 2] Dang quet Container da ap dung Multi-stage build & Hardening (Slide 10-11)...\n")
            run_cmd([HARDENED_FILE, "--ci"])
            print("\n[Luu y]: Container dat 100/100 diem va PASSED qua duong ong CI/CD!")
            input("\nNhan Enter de quay ve Menu...")
        elif choice == "4":
            clear()
            print("=" * 80)
            print("  BAT DAU KICH BAN QUAY VIDEO DEMO (TU DONG)")
            print("=" * 80)
            print("\n>>> BUOC 1: Quet Container gap loi nghiem trong (Slide 4 -> 9)...")
            time.sleep(1)
            run_cmd([VULN_FILE, "--ci"])
            print("\n" + "=" * 80)
            input(">> [Nhan Enter de Mo Giao Dien Bao Cao Trực Quan Dashboard (Slide 11)...]")
            if os.path.exists(REPORT_HTML):
                webbrowser.open("file://" + os.path.abspath(REPORT_HTML))
            print("\n>>> BUOC 2: Quet kiem tra lai voi Container da duoc Hardening (Slide 10 -> 12)...")
            time.sleep(2)
            run_cmd([HARDENED_FILE, "--ci"])
            print("\n" + "=" * 80)
            print("  [HOAN TAT DEMO] BAN CO THE DUNG QUAY VIDEO!")
            print("=" * 80)
            input("\nNhan Enter de quay ve Menu...")
        elif choice == "5":
            print("\nTam biet!")
            break

if __name__ == "__main__":
    menu()
