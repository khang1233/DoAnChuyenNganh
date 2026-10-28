"""
Script mở hộp thoại chọn thư mục chuẩn của Windows (Native Folder Browser Dialog)
Sử dụng tkinter với cờ topmost để hộp thoại luôn nổi lên trên cùng trình duyệt.
"""
import sys
import os

def pick_folder(initial_dir=None):
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        # Đưa cửa sổ lên trên cùng màn hình
        root.attributes('-topmost', True)
        root.focus_force()

        init = initial_dir if (initial_dir and os.path.exists(initial_dir)) else os.getcwd()
        folder_selected = filedialog.askdirectory(
            parent=root,
            initialdir=init,
            title="Chọn Thư Mục Dự Án / Mã Nguồn Cần Quét & Bảo Vệ"
        )
        root.destroy()
        return folder_selected or ""
    except Exception as e:
        # Fallback qua PowerShell nếu môi trường không có UI tkinter
        try:
            import subprocess
            ps_cmd = (
                "[System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null; "
                "$f = New-Object System.Windows.Forms.FolderBrowserDialog; "
                "$f.Description = 'Chọn Thư Mục Dự Án / Mã Nguồn Cần Quét & Bảo Vệ'; "
                "$top = New-Object System.Windows.Forms.Form -Property @{TopMost=$true}; "
                "if ($f.ShowDialog($top) -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.SelectedPath }"
            )
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=60)
            return res.stdout.strip()
        except Exception:
            return ""

if __name__ == "__main__":
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    result = pick_folder(initial)
    if result:
        # In ra đường dẫn dạng chuẩn slash
        print(os.path.abspath(result).replace("\\", "/"))
    else:
        sys.exit(1)
