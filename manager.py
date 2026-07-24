

import time
import subprocess
import json
import frida
import os


# Добавляем функцию, которая ловит сообщения и console.log() из JS
def on_message(message, data):
    if message['type'] == 'send':
        # Сюда прилетает чистый console.log() из хуков
        print(f"[Frida LOG]: {message['payload']}")
    elif message['type'] == 'error':
        # Сюда прилетят ошибки, если JS-код где-то упал
        print(f"[Frida ERROR]: {message['stack']}")


def main():
    # запускаем фоновый генератор мутаций в фоне
    generator_proc = subprocess.Popen(["python", "mutation_generator.py"])
    '''
    # 2. Подключаемся к Frida-server внутри WSL по сети
    print("[*] Connecting to Frida inside WSL...")
    device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    
    # подключаемся к процессу SoftEther 
    processNum = int(input("Input process num: "))
    session = device.attach(processNum)
    
    # читаем и загружаем скрипты хуков из файлов
    with open("hook.js", "r", encoding="utf-8") as f:
        hook_code = f.read()
    with open("hookControl.js", "r", encoding="utf-8") as f:
        hook_control_code = f.read()
        
    script_hook = session.create_script(hook_code)
    script_hook_control = session.create_script(hook_control_code)

    # Критично: связываем функцию on_message со скриптами перед их загрузкой
    script_hook.on('message', on_message)
    script_hook_control.on('message', on_message)

    script_hook.load()
    script_hook_control.load()
    print("Frida hooks injected successfully!")

    while True:
        a=1
    '''

    # Основной цикл фаззинга
    file_counter = 0
    filesNotFoundSequence = 0

    try:
        while True:
            # Формируем имя файла по счетчику
            filename = f"KEY_1/{file_counter:05d}.json"
            if filesNotFoundSequence > 100:
                break

            if os.path.exists(filename):
                filesNotFoundSequence = 0
                try:
                    # 1. Читаем текущий файл из папки KEY1
                    with open(filename, "r", encoding="utf-8") as f:
                        mutation_data = json.load(f)
                    
                    # 2. Перезаписываем его содержимое в cur_mutation.json для хуков
                    with open("cur_mutation.json", "w", encoding="utf-8") as f:
                        json.dump(mutation_data, f, ensure_ascii=False, indent=2)
                        
                    print(f"Применена мутация из файла: {filename}")
                except json.JSONDecodeError:
                    print(f"ERROR: Ошибка структуры JSON в файле {filename}, пропускаем...")
            else:
                file_counter += 1
                filesNotFoundSequence += 1
                print(f"FILE {filename} not found!")
                continue
            # Шагаем к следующему номеру в любом случае (был файл или нет)
            file_counter += 1
            
            
            # Передаем JSON-объект через встроенный механизм Frida
            # script_hook.post({'type': 'mutation', 'payload': mutation_data})
            # script_hook_control.post({'type': 'mutation', 'payload': mutation_data})
            
            # Запускаем OpenVPN клиент на Windows
            print("Launching OpenVPN Client...")
            # Используем Popen, чтобы скрипт не завис в ожидании, если пакет застрянет
            client_proc = subprocess.Popen([
                "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
                    "--config", "C:\\Users\\magar\\Desktop\\1000101\\NIR\\msi_openvpn_remote_access_l3.ovpn"
                
            ])
            
            # Ждем пока клиент закончит работу
            time.sleep(10.0)
            
            # Принудительно гасим клиент для следующей итерации
            client_proc.terminate()
            client_proc.wait()
            print("Iteration finished.\n" + "-"*30)

    except KeyboardInterrupt:
        # ДОБАВИТЬ ВЫКЛЮЧЕНИЕ ГЕНЕРАТОРА
        exit()
            

if __name__ == "__main__":
    main()