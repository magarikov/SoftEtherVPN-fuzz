


import os
import time
from google import genai
from google.genai import types

def run_fuzzing_generation(prompt_file_path, output_dir="KEY_1"):

    # Вставляем твой токен напрямую
    MY_API_KEY = "AQ.Ab8RN6Lp6OGDc1gySv1xJxrd-LIc1CYU6dtTS_n08jZr21KvaQ" 
    
    # Инициализируем клиента Gemini
    client = genai.Client(api_key=MY_API_KEY)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Читаем главный промпт
    with open(prompt_file_path, "r", encoding="utf-8") as f:
        system_instruction_text = f.read()

    instructions = [
        # Вектор 1: Ломание конечного автомата
        "Generate 15 unique mutation sequences focusing on sending out-of-order packets. Mutate offset 0 of message M3 to replace the valid control opcode with data packet opcodes or server-side opcodes like 8 or 9 to trigger early resource allocation. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to bypass early initialization. Forcefully mutate the MySessionId field at offset 1 in message M1 to match an already active session id or a series of dead session IDs to test state hijacking. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting message sequence tracking. In message M3, change the PacketId field at offset 18 to a massive value or a value lower than expected to trigger integer mismatches in c->MaxRecvPacketId comparison loop. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences for premature authentication triggers. Empty the entire body of message M3 using delete operation at offset 26 and insert valid key parameters structures usually found in message M9 to trick the parser state. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to test unexpected soft reset routines. Forcefully inject message code 3 into message M1 or M3 at offset 0 while simultaneously corrupting the session tracking bytes to break the state tree. Return data in strictly valid JSON format.",

        # Вектор 2: Выход за рамки массивов и порча списков
        "Generate 15 unique mutation sequences targeting the ACK list validation logic. In network messages like M3 or M6, mutate the NumAck field at offset 9 to values greater than OPENVPN_MAX_NUMACK to force the loop into parsing a fake massive AckPacketId array. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting the function OvsDeleteFromSendingControlPacketList. In message M6, insert a huge number of fake entries in the AckPacketId array and manipulate the size modifier to trigger an integer overflow during NewListFast and loop boundary verification. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to cause out-of-bounds reads in OvsParsePacket. Mutate the headers of message M1 or M3 by setting NumAck to a positive integer but forcing the packet size variable to a small layout to trick the pointer arithmetic into reading past the allocated socket buffer. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting string parsing boundaries in OvsPeekStringFromFifo. In message M17, completely delete the terminating null byte at the end of the string and fill the remaining range with long sequences of repeating hex data to look for memory leakage or buffer over-reads. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting function OvsParseKeyMethod2. In message M9, mutate the string structures by placing multiple nested or unclosed null bytes inside the OptionString field to break the loop counter logic in OvsReadStringFromBuf. Return data in strictly valid JSON format.",

        # Вектор 3: Переполнения буферов кучи и стека
        "Generate 15 unique mutation sequences targeting buffer overflow vulnerabilities inside OvsParseKeyMethod2. In message M9, choose offsets corresponding to ret->Username or ret->Password fields and use the insert operation to inject massive blocks of hexadecimal data to overflow fixed stack buffers. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting text command processing. In message M17, insert a massive block of repeating character codes immediately after the PUSH_REQUEST sequence and force the size tracking variable to a huge integer value to test for heap overflow vulnerabilities inside IPC modules. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to cause structure collisions. In message M9, locate the cipher list and environment variables fields, then use the replace operation to overwrite adjacent structure pointers in memory with repetitive long patterns to find memory allocation layout vulnerabilities. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting length mismatched allocations. In message M3, apply the insert operation to expand the payload area by hundreds of bytes while intentionally forcing the size parameter to stay unchanged to trick the dynamic subtraction logic into memory corruption. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to trigger memory allocation failure exhaustion. In message M9, generate huge nested strings within the PeerInfo field combined with extreme force-size parameters like 4096 to break dynamic string memory copy operations inside the server. Return data in strictly valid JSON format.",

        # Вектор 4: Строки форматирования и инъекции команд
        "Generate 15 unique mutation sequences looking for Format String Vulnerabilities. Target message M17 and replace the entire PUSH_REQUEST token with long sequences of format specifiers including repeating character blocks of percent-s, percent-x, percent-d, and percent-n to corrupt printf-based debugging routines. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting dynamic log string assembly in OvsLog. In message M9, inject complex combinations of percent characters and string escape specifiers directly into the Username or PeerInfo fields to trigger type confusion vulnerabilities inside logging format structures. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences testing command injection inside the asynchronous connection module. In message M17, replace the command layer with strings containing classic command execution delimiters such as semicolons, backticks, and shell escape flags to target OvsBeginIPCAsyncConnectionIfEmpty logic blocks. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting parameter parsing validation bugs. In message M9, inject malicious string parameters into the OptionString field containing unexpected configuration directives and system control symbols to verify option isolation checks. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences looking for format leaks in channel error handling. In message M3, inject percentage symbols and format characters into the client_hello extension payload to test if the string is mistakenly evaluated as a direct argument during error string generation. Return data in strictly valid JSON format."
    ]

    # Сквозной счетчик для создания уникальных имен файлов во всех циклах
    global_counter = 0

    # Цикл генерации
    while (1):
        for index, user_instruction in enumerate(instructions):
            # Имя файла на основе сквозного счетчика: 00000.json, 00001.json, 00020.json и т.д.
            filename = f"{global_counter:05d}.json"
            filepath = os.path.join(output_dir, filename)
            
            print(f"\n[{index+1}/{len(instructions)}] (Всего создано: {global_counter}) Обработка запроса для {filename}...")

            try:
                # Отправляем запрос к актуальной gemini-3.5-flash
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=user_instruction,
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction_text,
                        temperature=0.7,
                        # Заставляем бэкенд Google возвращать только чистый JSON-объект
                        response_mime_type="application/json"
                    ),
                )

                json_data = response.text

                # Сохраняем в файл
                with open(filepath, "w", encoding="utf-8") as out_file:
                    out_file.write(json_data)
                
                print(f"Создан файл: {filepath}")

            except Exception as e:
                print(f"ERROR: Ошибка на запросе {index} ({filename}): {e}")
                print("Skipping...")

            # Наращиваем общий счетчик файлов
            global_counter += 1

            # Небольшая пауза, чтобы не забивать лимиты
            time.sleep(1)


if __name__ == "__main__":
    prompt_path = "промт 12000.txt"
    
    if not os.path.exists(prompt_path):
        print(f"ERROR: file {prompt_path} not found!")
        exit()

    run_fuzzing_generation(prompt_path)





'''
import os
import time
from openai import OpenAI

def run_fuzzing_generation(prompt_file_path, output_dir="KEY_1"):

    MY_API_KEY = "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" 
    
    client = OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=MY_API_KEY
    )

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Читаем главный промпт
    with open(prompt_file_path, "r", encoding="utf-8") as f:
        system_instruction_text = f.read()


    instructions = [
        # Вектор 1: Ломание конечного автомата
        "Generate 15 unique mutation sequences focusing on sending out-of-order packets. Mutate offset 0 of message M3 to replace the valid control opcode with data packet opcodes or server-side opcodes like 8 or 9 to trigger early resource allocation. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to bypass early initialization. Forcefully mutate the MySessionId field at offset 1 in message M1 to match an already active session id or a series of dead session IDs to test state hijacking. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting message sequence tracking. In message M3, change the PacketId field at offset 18 to a massive value or a value lower than expected to trigger integer mismatches in c->MaxRecvPacketId comparison loop. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences for premature authentication triggers. Empty the entire body of message M3 using delete operation at offset 26 and insert valid key parameters structures usually found in message M9 to trick the parser state. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to test unexpected soft reset routines. Forcefully inject message code 3 into message M1 or M3 at offset 0 while simultaneously corrupting the session tracking bytes to break the state tree. Return data in strictly valid JSON format.",

        # Вектор 2: Выход за рамки массивов и порча списков
        "Generate 15 unique mutation sequences targeting the ACK list validation logic. In network messages like M3 or M6, mutate the NumAck field at offset 9 to values greater than OPENVPN_MAX_NUMACK to force the loop into parsing a fake massive AckPacketId array. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting the function OvsDeleteFromSendingControlPacketList. In message M6, insert a huge number of fake entries in the AckPacketId array and manipulate the size modifier to trigger an integer overflow during NewListFast and loop boundary verification. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to cause out-of-bounds reads in OvsParsePacket. Mutate the headers of message M1 or M3 by setting NumAck to a positive integer but forcing the packet size variable to a small layout to trick the pointer arithmetic into reading past the allocated socket buffer. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting string parsing boundaries in OvsPeekStringFromFifo. In message M17, completely delete the terminating null byte at the end of the string and fill the remaining range with long sequences of repeating hex data to look for memory leakage or buffer over-reads. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting function OvsParseKeyMethod2. In message M9, mutate the string structures by placing multiple nested or unclosed null bytes inside the OptionString field to break the loop counter logic in OvsReadStringFromBuf. Return data in strictly valid JSON format.",

        # Вектор 3: Переполнения буферов кучи и стека
        "Generate 15 unique mutation sequences targeting buffer overflow vulnerabilities inside OvsParseKeyMethod2. In message M9, choose offsets corresponding to ret->Username or ret->Password fields and use the insert operation to inject massive blocks of hexadecimal data to overflow fixed stack buffers. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting text command processing. In message M17, insert a massive block of repeating character codes immediately after the PUSH_REQUEST sequence and force the size tracking variable to a huge integer value to test for heap overflow vulnerabilities inside IPC modules. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to cause structure collisions. In message M9, locate the cipher list and environment variables fields, then use the replace operation to overwrite adjacent structure pointers in memory with repetitive long patterns to find memory allocation layout vulnerabilities. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting length mismatched allocations. In message M3, apply the insert operation to expand the payload area by hundreds of bytes while intentionally forcing the size parameter to stay unchanged to trick the dynamic subtraction logic into memory corruption. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences to trigger memory allocation failure exhaustion. In message M9, generate huge nested strings within the PeerInfo field combined with extreme force-size parameters like 4096 to break dynamic string memory copy operations inside the server. Return data in strictly valid JSON format.",

        # Вектор 4: Строки форматирования и инъекции команд
        "Generate 15 unique mutation sequences looking for Format String Vulnerabilities. Target message M17 and replace the entire PUSH_REQUEST token with long sequences of format specifiers including repeating character blocks of percent-s, percent-x, percent-d, and percent-n to corrupt printf-based debugging routines. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting dynamic log string assembly in OvsLog. In message M9, inject complex combinations of percent characters and string escape specifiers directly into the Username or PeerInfo fields to trigger type confusion vulnerabilities inside logging format structures. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences testing command injection inside the asynchronous connection module. In message M17, replace the command layer with strings containing classic command execution delimiters such as semicolons, backticks, and shell escape flags to target OvsBeginIPCAsyncConnectionIfEmpty logic blocks. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences targeting parameter parsing validation bugs. In message M9, inject malicious string parameters into the OptionString field containing unexpected configuration directives and system control symbols to verify option isolation checks. Return data in strictly valid JSON format.",
        "Generate 15 unique mutation sequences looking for format leaks in channel error handling. In message M3, inject percentage symbols and format characters into the client_hello extension payload to test if the string is mistakenly evaluated as a direct argument during error string generation. Return data in strictly valid JSON format."
    ]

    # Цикл генерации
    while (1):
        for index, user_instruction in enumerate(instructions):
            # Форматируем имя файла: 00000.json, 00001.json и т.д.
            filename = f"{index:05d}.json"
            filepath = os.path.join(output_dir, filename)
            
            print(f"\n[{index+1}/{len(instructions)}] Обработка запроса для {filename}...")

            try:
                response = client.chat.completions.create(
                    model='llama-3.3-70b-versatile',
                    messages=[
                        {"role": "system", "content": system_instruction_text},
                        {"role": "user", "content": user_instruction}
                    ],
                    temperature=0.7,
                    response_format={"type": "json_object"}
                )

                json_data = response.choices[0].message.content


                with open(filepath, "w", encoding="utf-8") as out_file:
                    out_file.write(json_data)
                
                print(f"Создан файл: {filepath}")

            except Exception as e:
                print(f"ERROR: Ошибка на запросе {index} ({filename}): {e}")
                print("Skipping...")

            # Пауза 3 секунды, чтобы бесплатный лимит Groq не ругался на Rate Limit
            time.sleep(3)


if __name__ == "__main__":
    prompt_path = "промт 12000.txt"
    
    if not os.path.exists(prompt_path):
        print(f"ERROR: file {prompt_path} not found!")
        exit()

    run_fuzzing_generation(prompt_path)

'''



'''
from google import genai
from google.genai import types

def generate_fuzzing_case(prompt_file_path, user_instruction):
    # Вставляем ключ прямо строкой в код
    MY_API_KEY = "AQ.Ab8RN6Lp6OGDc1gySv1xJxrd-LIc1CYU6dtTS_n08jZr21KvaQ" 
    client = genai.Client(api_key=MY_API_KEY)

    try:
        with open(prompt_file_path, "r", encoding="utf-8") as f:
            system_instruction_text = f.read()
    except FileNotFoundError:
        print(f"Ошибка: Файл {prompt_file_path} не найден.")
        return

    print("[*] Отправка запроса в Gemini...")

    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents="Generate 20 unique mutation sequences to disrupt state machine.",
        config=types.GenerateContentConfig(
            system_instruction=system_instruction_text,
            temperature=0.7,
            # Этот параметр заставляет модель отвечать строго валидным JSON-объектом
            response_mime_type="application/json" 
        ),
    )

    print("\n[+] Ответ от модели:")
    print(response.text)

if __name__ == "__main__":
    prompt_path = "промт для модели.txt"
    instruction = "Generate a sequence of 3 mutations focusing on State Machine Disruption for M3 packet."
    
    generate_fuzzing_case(prompt_path, instruction)

'''