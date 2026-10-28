# -*- coding: utf-8 -*-
"""
Script mở hộp thoại chọn thư mục chuẩn của Windows (Native Windows File Explorer Folder Dialog).
Sử dụng ctypes + Tkinter với cờ Topmost và SetForegroundWindow để hộp thoại luôn nổi lên trên cùng trình duyệt.
"""
import sys
import os
import ctypes

def pick_folder(initial_dir=None):
    selected_path = ""
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.title("CTI File Explorer")
        root.geometry("1x1+0+0")
        root.attributes("-alpha", 0.0)
        root.attributes("-topmost", True)
        root.lift()
        root.focus_force()

        try:
            root.update()
            hwnd = root.winfo_id()
            ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass

        init = initial_dir if (initial_dir and os.path.exists(initial_dir)) else os.getcwd()
        selected_path = filedialog.askdirectory(
            parent=root,
            initialdir=init,
            title="Chọn Thư Mục Dự Án / Mã Nguồn Cần Quét & Bảo Vệ"
        )
        root.destroy()
    except Exception:
        pass

    if not selected_path:
        try:
            import subprocess
            ps_script = (
                "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null;\n"
                "$fbd = New-Object System.Windows.Forms.FolderBrowserDialog;\n"
                "$fbd.Description = 'Chọn Thư Mục Dự Án / Mã Nguồn Cần Quét & Bảo Vệ';\n"
                "$fbd.ShowNewFolderButton = $true;\n"
                "$fbd.AutoUpgradeEnabled = $true;\n"
                "$top = New-Object System.Windows.Forms.Form -Property @{TopMost=$true};\n"
                "$res = $fbd.ShowDialog($top);\n"
                "if ($res -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $fbd.SelectedPath }\n"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=60
            )
            selected_path = res.stdout.strip()
        except Exception:
            pass

    return selected_path

if __name__ == "__main__":
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    result = pick_folder(initial)
    if result:
        print(os.path.abspath(result).replace("\\", "/"))
        sys.exit(0)
    else:
        sys.exit(1)
