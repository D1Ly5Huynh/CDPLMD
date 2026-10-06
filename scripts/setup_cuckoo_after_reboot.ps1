# After Windows reboot (DISM 3010): start Ubuntu-22.04 and install Cuckoo 3 packages.
$ErrorActionPreference = "Stop"
$distro = "Ubuntu-22.04"
$script = "/mnt/c/Users/tuonghk/CDPLMD/scripts/install_cuckoo_wsl.sh"
$log = "C:\Users\tuonghk\CDPLMD\data\sources\cuckoo_wsl_install.log"

Write-Host "wsl status"
wsl --status
wsl -l -v
Write-Host "starting $distro"
wsl -d $distro -- bash -lc "uname -a; python3 --version; ls -l /dev/kvm || true"
if ($LASTEXITCODE -ne 0) {
    Write-Host "WSL still down. Reboot again or run: wsl --install --no-distribution"
    exit 1
}
Write-Host "install Cuckoo 3 into the distro (log $log)"
wsl -d $distro -- bash -lc "sed -i 's/\r$//' $script; bash $script" | Tee-Object -FilePath $log
Write-Host "exit=$LASTEXITCODE"
