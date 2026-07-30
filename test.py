
'''
import subprocess

kali_dir = '/mnt/c/Users/magar/Desktop/1000101/NIR'
pid = 920
window_title = "hook.js"

kali_command = f"cd {kali_dir} && echo 'maks' | sudo -S .venv/bin/frida -l 'hook.js' -p {pid}"

full_cmd = f'start "{window_title}" cmd /k wsl -d kali-linux -- bash -c "{kali_command}"'

subprocess.Popen(full_cmd, shell=True)
'''

import subprocess
client_proc = subprocess.Popen([
                                "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
                                    "--config", "C:\\Users\\magar\\Desktop\\1000101\\NIR\\msi_openvpn_remote_access_l3.ovpn"
                            ])