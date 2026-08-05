
'''
import subprocess

kali_dir = '/mnt/c/Users/magar/Desktop/1000101/NIR'
pid = 920
window_title = "hook.js"

kali_command = f"cd {kali_dir} && echo 'maks' | sudo -S .venv/bin/frida -l 'hook.js' -p {pid}"

full_cmd = f'start "{window_title}" cmd /k wsl -d kali-linux -- bash -c "{kali_command}"'

subprocess.Popen(full_cmd, shell=True)
'''
def test():
    global KEY
    if KEY:
        print("ERROR: .env file not found and keys are empty!")
        exit()

test()