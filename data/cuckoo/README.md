# Cuckoo (IF-MalEvade §IV)

Cuckoo so `signatures` mẫu gốc với mẫu đã mutate. Khớp thì giữ (paper: fully-working malware).

## Host

Cuckoo 3 (cert-ee) chạy trên **Ubuntu 22.04 WSL2**. Packages nằm ở `~/.cuckoo-venv`, CWD ở `~/.cuckoocwd`.

```powershell
cd C:\Users\tuonghk\CDPLMD
powershell -ExecutionPolicy Bypass -File scripts\setup_cuckoo_after_reboot.ps1
wsl -d Ubuntu-22.04 -- bash /mnt/c/Users/tuonghk/CDPLMD/scripts/migrate_and_start_cuckoo_api.sh
```

API: `http://127.0.0.1:8090` (`cuckoo api`). Guest Windows (VMCloak / Win10 ISO) là bước riêng — QEMU cần `/dev/kvm` (nestedVirtualization trong `%USERPROFILE%\.wslconfig`).

## Pipeline

`python run_experiment.py` ghi `cuckoo.status` nếu API `:8090` lên. Không có sandbox thì thí nghiệm ML vẫn chạy.

File mutate nằm dưới `data/cuckoo/work/` — không phát tán ra ngoài lab. Không gửi VirusTotal.
