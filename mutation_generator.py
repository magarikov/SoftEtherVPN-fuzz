
'''
This file is responcible for creating mutations.
It reads main promt and adds particular instruction to the current request
(ex. "try to cause buffer overflow").
The number of instructions is limited (20) and may be increased in future.

Because of a big amount of requests, I will separate them among different
LLM's, so each of it has more time to update request limits.

I also added "KEY_backup" file to save all generated files and 
remember which LLM generated each file.
This allows us to compare LLM's by the number of well-generated mutations
I will also change temperature to compare results.
'''

import os
import time
from google import genai
from google.genai import types
from openai import OpenAI
from openrouter import OpenRouter
import requests
import json
import random


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

# список доступных моделей (в ходе работы может уменьшаться, если модели недоступны)
models = ['gemini-3.5-flash-lite', 'gemini-3.1-flash-lite', 'gemini-3.6-flash', 'gemini-3.5-flash',
           'gemini-2.5-pro', 'nvidia/nemotron-nano-12b-v2-vl:free', 'inclusionai/ling-3.0-flash:free']

class Error(Exception):
    def __init__(self, code):
        self.code = code

# makes a request to LLM and returns json answer
def makeRequest(model, temp, user_instruction, system_instruction_text):

    if 'gemini' in model:
        client = genai.Client(api_key=GEMINI_KEY, http_options=types.HttpOptions(timeout=60000))
        response = client.models.generate_content(
                        model=model,
                        contents=user_instruction,
                        config=types.GenerateContentConfig(
                            system_instruction=system_instruction_text,
                            temperature=temp,
                            # Заставляем возвращать только чистый JSON-объект
                            response_mime_type="application/json"
                        ),
                    )
        response = response.text
    
    elif model == "gpt-5.4-mini":
        client = OpenAI(api_key=OPENAI_KEY)
        response = client.chat.completions.create(
            model="gpt-5.4-mini",
            temperature=temp,
            messages=[
                {"role": "system", "content": system_instruction_text},
                {"role": "user", "content": user_instruction}
            ],
            response_format={"type": "json_object"},
        )
        response = response.text

    elif model == "nvidia/nemotron-nano-12b-v2-vl:free":
        response = requests.post(
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_KEY}",
            "Content-Type": "application/json",
        },
        
        data=json.dumps({
            "model": 'nvidia/nemotron-nano-12b-v2-vl:free', #,'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free'
            "messages": [
                {"role": "system", "content": system_instruction_text},
                {"role": "user", "content": user_instruction}
            ],
            "reasoning": {"enabled": False}
        }),
        timeout=10
        )
        try:
            response = response.json()
            response = response["choices"][0]["message"]["content"]
        except Exception as e:  
            raise Error(429)
        

    elif model == "inclusionai/ling-3.0-flash:free":
        response = requests.post(
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_KEY}",
            "Content-Type": "application/json",
        },
        
        data=json.dumps({
            "model": 'inclusionai/ling-3.0-flash:free', #,'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free'
            "messages": [
                {"role": "system", "content": system_instruction_text},
                {"role": "user", "content": user_instruction}
            ],
            "reasoning": {"enabled": False}
        }),
        timeout=10
        )
        try:
            response = response.json()
            response = response["choices"][0]["message"]["content"]
        except Exception as e:  
            raise Error(429)

    return response



def run_fuzzing_generation(prompt_file_path, output_dir="KEY_1", output_dir_backup="KEY_backup"):

    # готовим пространство, загружаем промт
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with open(prompt_file_path, "r", encoding="utf-8") as f:
        system_instruction_text = f.read()

    # счетчик для создания уникальных имен файлов во всех циклах
    global_counter = 0
    # счетчик для папки KEY_backup
    # всё, что с _backup идет 
    global_counter_backup = 0

    '''
    ЦИКЛ ГЕНЕРАЦИИ
    Для каждой инструкции запускаем каждую доступную модель. Результат записываем в 2 файла:
    первый в папку KEY_1, второй в KEY_backup. Из первой папки будут браться файлы для фаззинга, после 
    того, как они испытаны они будут удалены. Во второй папке они сохраняются навсегда. 
    Плюс к этому, во второй папке хранится информация по всем генерациям (какой моделью
    сгенерирован файл, с какой температурой...)
    '''
    while (1):
        for index, user_instruction in enumerate(instructions):
            for model in models:
                
                # Имя файла на основе счетчика: 00000.json, 00001.json, 00020.json и т.д.
                filename = f"{global_counter:05d}.json"
                filename_backup = f"{global_counter_backup:05d}.json"
                filepath = os.path.join(output_dir, filename)
                filepath_backup = os.path.join(output_dir_backup, filename_backup)
                
                # пропускаем, если файл с таким именем уже есть
                if os.path.exists(filepath):
                    global_counter += 1
                    break # переходим к следующей итерации ПО INSTRUCTIONS
                while os.path.exists(filepath_backup):
                    global_counter_backup += 1
                    filename_backup = f"{global_counter_backup:05d}.json"
                    filepath_backup = os.path.join(output_dir_backup, filename_backup)

                print(f"\n Обработка запроса для {filename}...")

                try:
                    temperature = random.randint(50, 140) / 100
                    json_data = makeRequest(model, temperature, user_instruction, system_instruction_text)

                    # Сохраняем в файл
                    with open(filepath, "w", encoding="utf-8") as out_file:
                        out_file.write(json_data)
                    with open(filepath_backup, "w", encoding="utf-8") as out_file:
                        out_file.write(json_data)
                    
                    print(f"Создан файл: {filepath}")

                    with open(f"{output_dir_backup}/info.txt", "a+") as f:
                        f.write(f"\n{filename_backup} {index} {temperature:0.2f} {model}")

                    # увеличиваем счетчик файлов
                    global_counter += 1

                except Exception as e:
                    try:
                        if (e.code == 429) or ('429' in e.message): # если исчерпали лимит запросов
                            models.remove(model) # удаляем модель из списка доступных
                    except Exception as e2:  
                        pass
                    print(f"ERROR: Ошибка на запросе {index} ({filename}): {e}")
                    print("Skipping...")

                # Небольшая пауза, чтобы не выйти за лимиты
                time.sleep(15)

def init():
    global GEMINI_KEY, OPENROUTER_KEY, prompt_path

    if os.path.exists(".env"):
        GEMINI_KEY = os.getenv("GEMINI_KEY")
        OPENROUTER_KEY = os.getenv("OPENROUTER_KEY")
    else:
        print("ERROR: .env file not found and keys are empty!")
        exit()

    prompt_path = "data/промт 12000.txt"
    if not os.path.exists(prompt_path):
        print(f"ERROR: file {prompt_path} not found!")
        exit()

if __name__ == "__main__":

    init()
    run_fuzzing_generation(prompt_path)


