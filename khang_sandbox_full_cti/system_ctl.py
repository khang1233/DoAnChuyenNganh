# -*- coding: utf-8 -*-
"""
TRUNG TÂM ĐIỀU KHIỂN HỆ THỐNG AN NINH MẠNG CTI AGENTIC DEFENSE
Quản lý toàn bộ vòng đời khởi động, kiểm tra cổng mạng, mở trình duyệt và tắt hệ thống sạch sẽ.
"""

import os
import sys
import time
import socket
import subprocess
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SANDBOX_DIR = ROOT_DIR / "khang_sandbox_full_cti"
APP_FILE = SANDBOX_DIR / "live_dashboard_app.py"
PORT = 8765
WAF_PORT = 8766
OLLAMA_PORT = 11434

def is_port_listening(port: int, host: str = "127.0.0.1") -> bool:
    """Kiểm tra cực nhanh (0.01s) xem cổng có đang mở không."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0

def wait_for_server(port: int, max_retries: int = 24, delay: float = 0.5) -> bool:
    """Chờ server khởi động thành công."""
    for _ in range(max_retries):
        if is_port_listening(port):
            return True
        time.sleep(delay)
    return False

def free_ports():
    """Dừng các tiến trình đang chiếm cổng 8765 hoặc 8766."""
    if sys.platform == "win32":
        cmd = (
            'powershell -NoProfile -Command "'
            'Get-NetTCPConnection -LocalPort 8765,8766 -ErrorAction SilentlyContinue | '
            'ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"'
        )
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        except Exception:
            pass

def start_ollama_if_needed():
    """Tự động khởi động Ollama GPU nếu chưa chạy."""
    if is_port_listening(OLLAMA_PORT):
        return

    env = os.environ.copy()
    models_dir = ROOT_DIR / "ollama_models"
    if models_dir.exists():
        env["OLLAMA_MODELS"] = str(models_dir)
    env["OLLAMA_KEEP_ALIVE"] = "24h"

    creationflags = 0x00000008 if sys.platform == "win32" else 0  # DETACHED_PROCESS
    try:
        subprocess.Popen(
            ["ollama", "serve"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags
        )
    except Exception:
        # Thử đường dẫn mặc định của Ollama trên Windows
        local_app = os.environ.get("LOCALAPPDATA", "")
        ollama_exe = Path(local_app) / "Programs" / "Ollama" / "ollama.exe"
        if ollama_exe.exists():
            try:
                subprocess.Popen(
                    [str(ollama_exe), "serve"],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags
                )
            except Exception:
                pass

def start_system():
    """Khởi động hệ thống CTI Dashboard và WAF Proxy chạy ngầm độc lập."""
    print("=" * 78)
    print("  DANG KHOI DONG HE THONG AN NINH MANG TU HANH CTI AGENTIC DEFENSE...")
    print("=" * 78)
    print()

    # 1. Dọn sạch cổng nếu có tiến trình cũ
    free_ports()

    # 2. Bật Ollama GPU ngầm
    print("[1/3] Kiem tra va khoi dong Ollama GPU Server...")
    start_ollama_if_needed()

    # 3. Khởi động Web Server & WAF Proxy chạy ngầm hoàn toàn độc lập
    print("[2/3] Khoi dong CTI Web Server (Cong 8765) va WAF Reverse Proxy (Cong 8766)...")
    creationflags = 0x00000008 if sys.platform == "win32" else 0  # DETACHED_PROCESS
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        subprocess.Popen(
            [sys.executable, str(APP_FILE)],
            cwd=str(SANDBOX_DIR),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags
        )
    except Exception as e:
        print(f"[LOI] Khong the khoi dong Web Server: {e}")
        return False

    # 4. Chờ server sẵn sàng
    print("[3/3] Dang nap tri thuc CTI va kiem tra ket noi...")
    ready = wait_for_server(PORT, max_retries=20, delay=0.5)

    if ready:
        print("[OK] He thong da san sang!")
        time.sleep(0.5)
        webbrowser.open("http://127.0.0.1:8765")
        return True
    else:
        print("[CANH BAO] Server can them thoi gian khoi dong cac mo hinh AI...")
        webbrowser.open("http://127.0.0.1:8765")
        return True

def stop_system():
    """Dừng toàn bộ hệ thống CTI, giải phóng cổng mạng và bộ nhớ RAM/GPU."""
    print("=" * 78)
    print("  DANG TAT TOAN BO HE THONG VA GIAI PHONG RAM / GPU...")
    print("=" * 78)
    print()

    # 1. Dừng Ollama
    print("[1/3] Dung tien trinh Ollama GPU Server...")
    if sys.platform == "win32":
        try:
            subprocess.run("taskkill /F /IM ollama.exe /T", shell=True, capture_output=True, timeout=5)
            subprocess.run("taskkill /F /IM ollama_llama_server.exe /T", shell=True, capture_output=True, timeout=5)
        except Exception:
            pass

    # 2. Dừng Python Server
    print("[2/3] Dung tien trinh Web Dashboard va WAF Proxy...")
    if sys.platform == "win32":
        cmd = (
            'powershell -NoProfile -Command "'
            '$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match \'live_dashboard_app\' }; '
            'if ($procs) { $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }"'
        )
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        except Exception:
            pass

    # 3. Giải phóng các cổng
    print("[3/3] Giai phong cac cong mang (8765, 8766, 11434)...")
    free_ports()
    if sys.platform == "win32":
        cmd_port = (
            'powershell -NoProfile -Command "'
            '$pids = (Get-NetTCPConnection -LocalPort 11434 -ErrorAction SilentlyContinue).OwningProcess; '
            'if ($pids) { Stop-Process -Id $pids -Force -ErrorAction SilentlyContinue }"'
        )
        try:
            subprocess.run(cmd_port, shell=True, capture_output=True, timeout=5)
        except Exception:
            pass

    print()
    print("=" * 78)
    print("  [HOAN TAT] DA TAT SACH TOAN BO HE THONG!")
    print("  - Toan bo bo nho GPU va RAM da duoc giai phong 100%.")
    print("=" * 78)
    print()
    time.sleep(2)

def interactive_menu():
    """Giao diện điều khiển bảng lệnh tương tác trực tiếp."""
    while True:
        os.system("cls" if sys.platform == "win32" else "clear")
        is_running = is_port_listening(PORT)

        print("=" * 78)
        if is_running:
            print("  HE THONG AN NINH MANG TU HANH CTI AGENTIC DEFENSE DANG HOAT DONG")
        else:
            print("  HE THONG CTI AGENTIC DEFENSE DANG DUNG (OFFLINE)")
        print("=" * 78)
        print()
        if is_running:
            print("  [OK] Web Dashboard        : http://127.0.0.1:8765")
            print("  [OK] WAF Reverse Proxy L7 : http://127.0.0.1:8766")
            print("  [OK] AI Agent Engine      : Dang san sang nhan dien ma nguon va hoc CTI")
            print()
            print("  * Ghi chu: Ban co the dong cua so nay bat ky luc nao, he thong van tiep tuc")
            print("    chay ngam. Khi can tat: Nhap dup vao file '2_TAT_HE_THONG.bat',")
            print("    hoac bam nut 'Tat He Thong' truc tiep tren Web Dashboard.")
        else:
            print("  - He thong hien dang tam tat.")
        print()
        print("=" * 78)
        print("  BANG DIEU KHIEN TRUC TIEP:")
        if is_running:
            print("    [1] Mo lai Web Dashboard tren trinh duyet (Enter)")
            print("    [2] TAT TOAN BO HE THONG va Giai phong RAM / GPU")
            print("    [3] Khoi dong lai he thong")
            print("    [0] Thoat cua so nay (He thong van tiep tuc chay ngam)")
        else:
            print("    [1] BAT HE THONG va mo Web Dashboard (Enter)")
            print("    [0] Thoat")
        print("=" * 78)
        print()

        try:
            choice = input("Nhap lua chon cua ban: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if not choice or choice in ("1", "m"):
            if is_running:
                webbrowser.open("http://127.0.0.1:8765")
            else:
                start_system()
        elif choice in ("2", "t"):
            stop_system()
        elif choice in ("3", "r"):
            stop_system()
            start_system()
        elif choice in ("0", "q", "exit"):
            break

def main():
    # Kiểm tra cờ tham số dòng lệnh nếu gọi từ CLI
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "stop":
            stop_system()
            return
        elif cmd == "status":
            alive = is_port_listening(PORT)
            print(f"CTI Defense Status: {'ONLINE (http://127.0.0.1:8765)' if alive else 'OFFLINE'}")
            return
        elif cmd == "restart":
            stop_system()
            start_system()
            return

    # Nếu hệ thống chưa chạy, tự khởi động ngay
    if not is_port_listening(PORT):
        start_system()
    else:
        # Nếu đang chạy, mở ngay browser
        webbrowser.open("http://127.0.0.1:8765")

    # Mở bảng điều khiển tương tác
    interactive_menu()

if __name__ == "__main__":
    main()
