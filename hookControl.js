
// Используем setTimeout, чтобы дать системе время прогрузить библиотеки
setTimeout(function() {
    var moduleName = "libcedar.so";
    var funcName = "OvsProcessRecvControlPacket";

    var module = Process.findModuleByName(moduleName);

    if (module) {
        console.log("Module " + moduleName + " found. Base: " + module.base);

        var funcPtr = module.findExportByName(funcName);
        if (funcPtr) {
            var hookAddr = funcPtr.add(0x435); // 435 - смещение внутри функции до нужной точки, где данные уже расшифрованы
            console.log("Hook successfully placed to " + hookAddr);

            Interceptor.attach(hookAddr, {
                onEnter: function (args) {
                    console.log("OvsProcessRecvControlPacket called!");
                    
                    var mutation = JSON.parse(new File("/mnt/c/Users/magar/Desktop/1000101/NIR/data/cur_mutation.json", "r").readText());
                    

                    try {
                        // Извлекаем указатель на структуру OPENVPN_CHANNEL c из регистра R14
                        var c = this.context.r14;
                        if (c.isNull()) return;

                        // 1. Читаем c->SslPipe (смещение +48)
                        var sslPipe = c.add(48).readPointer();
                        if (sslPipe.isNull()) return;

                        // 2. Читаем sslPipe->SslInOut (смещение +24)
                        var sslInOut = sslPipe.add(24).readPointer();
                        if (sslInOut.isNull()) return;

                        // 3. Читаем sslInOut->RecvFifo (смещение +16)
                        var recvFifo = sslInOut.add(16).readPointer();
                        if (recvFifo.isNull()) return;

                        // 4. Парсим структуру FIFO
                        var fifoBufPtr = recvFifo.add(16).readPointer(); // Поле void *p (смещение +16)
                        var fifoSizePtr = recvFifo.add(28);
                        var fifoSize = recvFifo.add(28).readU32();      // Поле UINT size (смещение +28)

                        if (fifoSize > 0 && !fifoBufPtr.isNull()) {
                            console.log("\n=================== [ РАСШИФРОВАННЫЙ TLS PAYLOAD ] ===================");
                            console.log("Адрес FIFO буфера: " + fifoBufPtr + ", Размер: " + fifoSize + " байт");
                            
                            // Выводим дамп расшифрованного пакета
                            console.log(hexdump(fifoBufPtr, {
                                offset: 0,
                                length: fifoSize,
                                header: true,
                                ansi: false
                            }));

                            fifoSize = applyNetworkMutations(mutation, fifoBufPtr, fifoSizePtr, fifoSize);

                            if (fifoSize > 0 && fifoSize < 2000 && !fifoBufPtr.isNull()) {
                                console.log("------------------- [ ТЕЛО ПОСЛЕ МУТАЦИИ ] -------------------");
                                console.log(hexdump(fifoBufPtr, { length: fifoSize, header: true, ansi: true }));
                            }
                            console.log("=====================================================================\n");
                        }
                    } catch (error) {
                        console.log("[!] Критическая ошибка при разборе структур памяти: " + error.message);
                    }
                }
            });
            
        } 
        else {
            console.log("ERROR: Hook hasn't been placed.");
        }
            
    } else {
        console.log("ERROR: module " + moduleName + " isn't found.");
    }
}, 500);





function applyNetworkMutations(mutationArray, dataPtr, currentSizePtr, packetSize) {

    if (!mutationArray || mutationArray.length === 0) return packetSize;

    var newSize = packetSize;
    // Создаем временный JS-буфер из памяти, чтобы с ним было легче работать
    var buffer = dataPtr.readByteArray(packetSize);
    var u8Array = new Uint8Array(buffer);
    console.log(mutationArray.length)
    for (var i = 0; i < mutationArray.length; i++) {
        
        var mut = mutationArray[i];
        console.log(JSON.stringify(mut));
        // Проверяем условия применимости (M17 и размер 13) ИЛИ (M9 и размер больше 200)
        var isM1 = (mut.msg === "M17" && packetSize === 13);
        var isM3 = (mut.msg === "M9" && packetSize > 200);

        if (!isM1 && !isM3) continue;

        // Переводим HEX-строку мутации в массив байт
        var valBytes = [];
        if (mut.val && mut.val.length > 0) {
            for (var j = 0; j < mut.val.length; j += 2) {
                valBytes.push(parseInt(mut.val.substr(j, 2), 16));
            }
        }

        // Парсим смещение (число или массив [start, end])
        var startOffset = 0;
        var endOffset = 0;
        var isRange = Array.isArray(mut.offset);

        if (isRange) {
            startOffset = mut.offset[0];
            endOffset = mut.offset[1];
        } else {
            startOffset = mut.offset;
            endOffset = startOffset;
        }

        // 1. Операция REPLACE ("r")
        if (mut.op === "r") {
            if (isRange) {
                // Если диапазон, забиваем его циклически или одним байтом
                var byteToRepeat = valBytes[0] || 0;
                for (var o = startOffset; o <= endOffset && o < u8Array.length; o++) {
                    u8Array[o] = byteToRepeat;
                }
            } else {
                // Одиночная замена последовательности байт
                for (var b = 0; b < valBytes.length; b++) {
                    if ((startOffset + b) < u8Array.length) {
                        u8Array[startOffset + b] = valBytes[b];
                    }
                }
            }
        }

        // 2. Операция DELETE ("d")
        else if (mut.op === "d") {
            var deleteLen = isRange ? (endOffset - startOffset + 1) : 1;
            if (startOffset < u8Array.length) {
                var nextBytes = u8Array.subarray(startOffset + deleteLen);
                u8Array.set(nextBytes, startOffset);
                // Уменьшаем логический размер нашего рабочего массива
                newSize -= deleteLen;
                u8Array = u8Array.subarray(0, newSize);
            }
        }

        // 3. Операция INSERT ("i")
        else if (mut.op === "i") {
            if (isRange) {
                var insertLen = endOffset - startOffset;
                // формируем новый, расширенный массив
                var extendedArray = new Uint8Array(newSize + insertLen);
                // Копируем до смещения
                extendedArray.set(u8Array.subarray(0, startOffset), 0);
                // Вставляем новые байты
                extendedArray.set(valBytes, startOffset);
                // Сдвигаем хвост
                extendedArray.set(u8Array.subarray(startOffset), startOffset + insertLen);
                
                u8Array = extendedArray;
                newSize += insertLen;
            }
            else {
                // почти так же, только считаем длину для вставки
                var insertLen = valBytes.length;
                if (startOffset <= u8Array.length) {
                    var extendedArray = new Uint8Array(newSize + insertLen);
                    extendedArray.set(u8Array.subarray(0, startOffset), 0);
                    extendedArray.set(valBytes, startOffset);
                    extendedArray.set(u8Array.subarray(startOffset), startOffset + insertLen);
                    u8Array = extendedArray;
                    newSize += insertLen;
                }
            }
        }

        // 4. Обработка флага "size" внутри объекта мутации
        if (mut.size !== "-") {
            var forcedSize = int(mut.size);
            // Если в рамках одной цепочки для этого сообщения задан жесткий размер — форсим его
            currentSizePtr.writeU32(forcedSize);
            // Записываем измененный буфер обратно в память сервера
            dataPtr.writeByteArray(u8Array.buffer.slice(0, u8Array.length));
            console.log("[!] Размер принудительно изменен на: " + forcedSize);
            return forcedSize;
        }
    }

    // Записываем финальный измененный массив байт обратно по адресу dataPtr кучи
    dataPtr.writeByteArray(u8Array.buffer.slice(0, u8Array.length));
    
    // Если флаг "size" был "-", записываем посчитанный нами новый размер
    currentSizePtr.writeU32(newSize);
    console.log("[+] Новый расчетный размер пакета записан в память: " + newSize);
    
    return newSize;
}

