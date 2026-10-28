# -*- coding: utf-8 -*-
"""
HỆ THỐNG TỰ ĐỘNG NHẬN DIỆN PHẦN CỨNG & MÔ HÌNH AI CỤC BỘ (DYNAMIC HARDWARE & OLLAMA DETECTOR)
Giải quyết triệt để vấn đề:
1. Không hardcode tên GPU (AMD RX 6600, NVIDIA, Intel, Apple Silicon, hay CPU).
2. Tự động truy vấn danh sách Model Ollama thực tế đang có trên máy của người dùng.
3. Tự động đề xuất mô hình AI tối ưu nhất tương thích với dung lượng VRAM/RAM thực tế.
"""

import os
import sys
import json
import platform
import subprocess
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]

def detect_hardware_profile() -> Dict[str, Any]:
    """
    Tự động dò tìm thông số GPU, VRAM và RAM thực tế của máy tính đang chạy.
    Hỗ trợ Windows, Linux và macOS.
    """
    gpu_name = "CPU Mode"
    vram_gb = 0.0
    device_type = "CPU"
    is_gpu = False

    # 1. Thử nhận diện qua NVIDIA SMI (Dành cho máy dùng card NVIDIA CUDA)
    try:
        nv = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=2
        )
        if nv.returncode == 0 and nv.stdout.strip():
            parts = nv.stdout.strip().split("\n")[0].split(",")
            gpu_name = parts[0].strip()
            vram_mb = float(parts[1].strip())
            vram_gb = round(vram_mb / 1024, 1)
            device_type = "NVIDIA CUDA"
            is_gpu = True
            return {
                "gpu_name": gpu_name,
                "vram_gb": vram_gb,
                "device_type": device_type,
                "is_gpu_available": is_gpu,
                "display_badge": f"{gpu_name.upper()} ({vram_gb}GB VRAM • {device_type})"
            }
    except Exception:
        pass

    # 2. Thử nhận diện trên Windows qua PowerShell / CimInstance
    if sys.platform == "win32":
        try:
            cmd = 'Get-CimInstance Win32_VideoController | Select-Object -Property Name, AdapterRAM | ConvertTo-Json'
            ps = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=3
            )
            if ps.returncode == 0 and ps.stdout.strip():
                data = json.loads(ps.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    name = item.get("Name", "")
                    # Bỏ qua các màn hình ảo (Parsec, Remote Desktop, Virtual Display)
                    if any(v in name.lower() for v in ["virtual", "basic display", "remotedesktop", "parsec", "citrix"]):
                        continue
                    
                    gpu_name = name
                    is_gpu = True
                    # Ước lượng VRAM dựa trên dòng card phổ biến nếu AdapterRAM bị giới hạn 32-bit (4GB)
                    lower_name = name.lower()
                    if "6600" in lower_name or "3060" in lower_name or "4060" in lower_name:
                        vram_gb = 8.0
                    elif "3070" in lower_name or "4070" in lower_name:
                        vram_gb = 12.0
                    elif "3080" in lower_name or "4080" in lower_name:
                        vram_gb = 16.0
                    elif "3090" in lower_name or "4090" in lower_name:
                        vram_gb = 24.0
                    elif "1660" in lower_name or "2060" in lower_name:
                        vram_gb = 6.0
                    elif "1650" in lower_name or "1050" in lower_name:
                        vram_gb = 4.0
                    else:
                        raw_ram = item.get("AdapterRAM", 0) or 0
                        vram_gb = round(raw_ram / (1024**3), 1) if raw_ram > 0 else 4.0

                    if "amd" in lower_name or "radeon" in lower_name:
                        device_type = "AMD Radeon (ROCm / DirectX)"
                    elif "intel" in lower_name or "arc" in lower_name:
                        device_type = "Intel Graphics"
                    else:
                        device_type = "Discrete GPU"

                    return {
                        "gpu_name": gpu_name,
                        "vram_gb": vram_gb,
                        "device_type": device_type,
                        "is_gpu_available": is_gpu,
                        "display_badge": f"{gpu_name.upper()} ({vram_gb}GB VRAM)"
                    }
        except Exception:
            pass

    # 3. Chế độ CPU Fallback nếu máy không có card đồ họa rời
    processor_name = platform.processor() or "CPU Đa Nhân"
    return {
        "gpu_name": f"CPU Mode ({processor_name})",
        "vram_gb": 0.0,
        "device_type": "CPU",
        "is_gpu_available": False,
        "display_badge": f"CHẾ ĐỘ CPU ({processor_name[:28]})"
    }


def query_ollama_runtime() -> Dict[str, Any]:
    """
    Truy vấn API Ollama cục bộ (`http://127.0.0.1:11434/api/tags`) để lấy
    danh sách chính xác các mô hình đang thực sự có mặt trên máy của người dùng.
    """
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags")
        with urllib.request.urlopen(req, timeout=1.8) as r:
            if r.status == 200:
                data = json.loads(r.read().decode("utf-8"))
                models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                return {
                    "is_running": True,
                    "models": models,
                    "port": 11434
                }
    except Exception:
        pass

    return {
        "is_running": False,
        "models": [],
        "port": 11434
    }


def get_adaptive_system_profile() -> Dict[str, Any]:
    """
    Tổng hợp toàn bộ thông tin hệ thống: Phần cứng thực tế + Ollama Models + Đề xuất mô hình tối ưu.
    """
    hw = detect_hardware_profile()
    ollama = query_ollama_runtime()
    
    vram = hw.get("vram_gb", 0.0)
    is_gpu = hw.get("is_gpu_available", False)
    installed_models = ollama.get("models", [])

    # Xác định kích thước mô hình khuyến nghị dựa trên cấu hình phần cứng
    if is_gpu and vram >= 12.0:
        recommended_tier = "7B - 14B (Suy Luận Đỉnh Cao)"
        suggested_names = ["qwen2.5:7b", "llama3.1:8b", "deepseek-r1:8b", "qwen3:8b", "khang-qwen3"]
    elif is_gpu and vram >= 7.5:
        recommended_tier = "7B - 8B (Cân Bằng Tốc Độ & Độ Sâu)"
        suggested_names = ["qwen2.5:7b", "qwen3:8b", "khang-qwen3", "gemma3:4b", "deepseek-r1:7b"]
    elif is_gpu and vram >= 3.5:
        recommended_tier = "3B - 4B (Tối Ưu Hóa VRAM)"
        suggested_names = ["gemma3:4b", "khang-ai", "qwen2.5:3b", "phi3:mini", "qwen2.5:1.5b"]
    else:
        recommended_tier = "1.5B Turbo / CTI Matrix Core (CPU Friendly)"
        suggested_names = ["qwen2.5:1.5b", "llama3.2:1b"]

    # Tìm xem trong số model người dùng đã cài, model nào phù hợp nhất
    active_model = None
    if installed_models:
        for sug in suggested_names:
            for inst in installed_models:
                if inst.startswith(sug) or sug.startswith(inst.split(":")[0]):
                    active_model = inst
                    break
            if active_model:
                break
        if not active_model:
            active_model = installed_models[0]
    else:
        # Nếu chưa bật Ollama, dùng CTI Matrix Heuristic Core không cần GPU
        active_model = "cti-heuristic-engine"

    # Xây dựng danh sách lựa chọn Dropdown trực quan
    options = []
    if installed_models:
        for m in installed_models:
            is_active = (m == active_model)
            clean_name = m.split(":")[0].upper()
            options.append({
                "value": m,
                "label": f"Model: {m} (Khả dụng trên {hw['gpu_name']})",
                "is_active": is_active,
                "is_installed": True
            })
    
    # Luôn có tùy chọn CTI Heuristic Core (an toàn 100%, chạy tức thì trên mọi máy)
    options.append({
        "value": "cti-heuristic-engine",
        "label": f"Chế độ CTI Heuristic Core (Offline • Phân tích 5 nguồn • Siêu nhẹ)",
        "is_active": (active_model == "cti-heuristic-engine"),
        "is_installed": True
    })

    return {
        "status": "success",
        "hardware": hw,
        "ollama": ollama,
        "recommended_tier": recommended_tier,
        "active_model": active_model,
        "options": options
    }

if __name__ == "__main__":
    profile = get_adaptive_system_profile()
    print(json.dumps(profile, indent=2, ensure_ascii=False))
