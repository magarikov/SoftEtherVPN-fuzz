

import time
import subprocess
import json
import os


def main():
    # запускаем фоновый генератор мутаций в фоне
    generator_proc = subprocess.Popen(["python", "mutation_generator.py"])

    # запускаем хуки
    kali_dir = '/mnt/c/Users/magar/Desktop/1000101/NIR'
    pid = int(input("Enter server pid: "))

    window_title = "Stalker.js"
    kali_command = f"cd {kali_dir} && echo 'maks' | sudo -S .venv/bin/frida -l 'Stalker.js' -p {pid}"
    full_cmd = f'start "{window_title}" cmd /k wsl -d kali-linux -- bash -c "{kali_command}"'
    subprocess.Popen(full_cmd, shell=True)

    window_title = "hook.js"
    kali_command = f"cd {kali_dir} && echo 'maks' | sudo -S .venv/bin/frida -l 'hook.js' -p {pid}"
    full_cmd = f'start "{window_title}" cmd /k wsl -d kali-linux -- bash -c "{kali_command}"'
    subprocess.Popen(full_cmd, shell=True)

    window_title = "hookControl.js"
    kali_command = f"cd {kali_dir} && echo 'maks' | sudo -S .venv/bin/frida -l 'hookControl.js' -p {pid}"
    full_cmd = f'start "{window_title}" cmd /k wsl -d kali-linux -- bash -c "{kali_command}"'
    subprocess.Popen(full_cmd, shell=True)

    # Ждем запуска хуков
    time.sleep(10.0)
    print("Mutation generator activated, hooks are placed.")


    # Основной цикл фаззинга
    fileCounter = 0
    stateCounter = 1 # номера состояний начинаются с единицы
    filesNotFoundSequence = 0

    try:
        # пробегаемся по файлам
        while True:
            # Формируем имя файла по счетчику
            filename = f"KEY_1/{fileCounter:05d}.json"

            if filesNotFoundSequence > 100:
                break

            if os.path.exists(filename):
                filesNotFoundSequence = 0
                try:
                    with open(filename, "r", encoding="utf-8") as f:
                        mutation_data = json.load(f)
                    
                    # Записываем состояния из файлов в cur_mutation.json для хуков
                    try:
                        while True:
                            stateName = f'S{str(stateCounter)}'
                            with open("data/cur_mutation.json", "w", encoding="utf-8") as f:
                                json.dump(mutation_data[stateName], f, ensure_ascii=False, indent=2)

                            # Запускаем OpenVPN клиент на Windows
                            # Используем Popen, чтобы скрипт не завис в ожидании, если пакет застрянет
                            client_proc = subprocess.Popen([
                                "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
                                    "--config", "C:\\Users\\magar\\Desktop\\1000101\\NIR\\msi_openvpn_remote_access_l3.ovpn"
                            ])
                            # Ждем пока клиент закончит работу
                            time.sleep(15.0)
                            # Принудительно гасим клиент для следующей итерации
                            client_proc.terminate()
                            client_proc.wait()
                            stateCounter += 1

                    except KeyError:
                        print(f"Применены мутации из файла: {filename}")
                    
                except json.JSONDecodeError:
                    print(f"ERROR: Ошибка структуры JSON в файле {filename}, пропускаем...")
            else:
                fileCounter += 1
                filesNotFoundSequence += 1
                print(f"FILE {filename} not found!")
                continue
            # Шагаем к следующему номеру в любом случае (был файл или нет)
            fileCounter += 1
        
            
            
            print("Iteration finished.\n" + "-"*30)

    except KeyboardInterrupt:
        # ДОБАВИТЬ ВЫКЛЮЧЕНИЕ ГЕНЕРАТОРА
        exit()
            

if __name__ == "__main__":
    main()