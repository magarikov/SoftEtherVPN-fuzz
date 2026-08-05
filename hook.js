
// Используем setTimeout, чтобы дать системе время прогрузить библиотеки
setTimeout(function() {
    var moduleName = "libcedar.so";
    var funcName = "OvsProceccRecvPacket"; // в названии опечатка

    var module = Process.findModuleByName(moduleName);

    if (module) {
        console.log("Module " + moduleName + " found. Base: " + module.base);
        
        // Ищем экспорт внутри конкретного модуля
        var funcPtr = module.findExportByName(funcName);

        var previousData;
        var numOfRepeats = 0;

        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {

                    //var p = args[1]; // Это адрес начала структуры UDPPACKET
                    //console.log(hexdump(args[1], { length: 128, header: false, ansi: true }));
                    //console.log("\n\n");
                    var mutation = JSON.parse(new File("/mnt/c/Users/magar/Desktop/1000101/NIR/data/cur_mutation.json", "r").readText());
                    
                    var p = args[1]; // Указатель на UDPPACKET
                    if (p.isNull()) return;

                    
                   

                    // 1 SrcIP — смещение 0, берем последние 4 байта из первой 16-байтной строки
                    var srcIpStr = p.add(12).readU8() + "." + p.add(13).readU8() + "." + p.add(14).readU8() + "." + p.add(15).readU8();
                    // 2 DstIP — смещение 32 = 20 + 12
                    var dstIpStr = p.add(32).readU8() + "." + p.add(33).readU8() + "." + p.add(34).readU8() + "." + p.add(35).readU8();
                    // 3 SrcPort — смещение 40 
                    var srcPort = p.add(40).readU32();
                    // 4 DestPort — смещение 44
                    var destPort = p.add(44).readU32();
                    // 5 Size — смещение 48 
                    var sizePtr = p.add(48);
                    var packetSize = p.add(48).readU32();
                    // 6 void *Data — смещение 56
                    var dataPtr = p.add(56).readPointer();
                    
                    if ((packetSize != 133) && (packetSize != 117) && (packetSize != 149) && (packetSize != 73) && (packetSize != 101) && (packetSize != 34) && (packetSize != 85)) {
                        console.log("\n=================== [ ПАРСИНГ ПО ДАМПУ ] ===================");
                        console.log("SrcIP: " + srcIpStr);
                        console.log("DstIP: " + dstIpStr);
                        console.log("SrcPort: " + srcPort);
                        console.log("DestPort: " + destPort);
                        console.log("Size: " + packetSize);
                        console.log("Data pointer: " + dataPtr);

                        // Выводим тело, если размеры сошлись с дампом (packetSize должен быть равен 14)
                        if (packetSize > 0 && packetSize < 2000 && !dataPtr.isNull()) {
                            console.log("------------------- [ ТЕЛО ПАКЕТА ] -------------------");
                            console.log(hexdump(dataPtr, { length: packetSize, header: true, ansi: true }));
                        }
                        
                        packetSize = applyNetworkMutations(mutation, dataPtr, sizePtr, packetSize);

                        if (packetSize > 0 && packetSize < 2000 && !dataPtr.isNull()) {
                            console.log("------------------- [ ТЕЛО ПОСЛЕ МУТАЦИИ ] -------------------");
                            console.log(hexdump(dataPtr, { length: packetSize, header: true, ansi: true }));
                        }
                        console.log("=============================================================\n");
                    }
                }
            });

            // Вспомогательная функция для красивого вывода байт в строку
            function bufToHex(buffer) {
                if (!buffer) return "null";
                var a = new Uint8Array(buffer);
                var hex = [];
                for (var i = 0; i < a.length; i++) {
                    var h = a[i].toString(16);
                    if (h.length < 2) h = "0" + h;
                    hex.push(h);
                }
                return hex.join(" ");
            }

            console.log("Hook successfully placed to " + funcName);
            

            
        } else {
            console.log("ERROR: Hook to OvsProceccRecvPacket hasn't been placed.");
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
        // Проверяем условия применимости (M1 и размер 14) ИЛИ (M3 и размер больше 200)
        var isM1 = (mut.msg === "M1" && packetSize === 14);
        var isM3 = (mut.msg === "M3" && packetSize > 200);

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
