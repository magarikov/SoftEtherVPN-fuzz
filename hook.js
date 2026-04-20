
// Используем setTimeout, чтобы дать системе время прогрузить библиотеки
setTimeout(function() {
    var moduleName = "libcedar.so";
    var funcName = "OvsProceccRecvPacket"; // Та самая опечатка

    var module = Process.findModuleByName(moduleName);

    if (module) {
        console.log("[+] Модуль " + moduleName + " найден! Base: " + module.base);
        
        // Ищем экспорт внутри конкретного модуля
        var funcPtr = module.findExportByName(funcName);

        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    var size = args[2].toInt32();
                    console.log("\n[*] Перехвачен пакет! Размер: " + size);
                    console.log(hexdump(args[1], { length: size > 32 ? 32 : size, header: true, ansi: true }));
                }
            });
            console.log("[+] Hook установлен на " + funcName);
        } else {
            console.log("[-] Ошибка: Функция не найдена. Проверь регистр.");
        }
    } else {
        console.log("[-] Модуль " + moduleName + " не найден в этом процессе. Попробуй другой PID.");
    }
}, 500);

/*
// Название модуля, который мы нашли
var moduleName = "libcedar.so";
// Имя функции с той самой опечаткой
var funcName = "OvsProceccRecvPacket";

// Ждем, пока модуль загрузится (на всякий случай)
var moduleBase = Module.findBaseAddress(moduleName);

if (moduleBase) {
    console.log("[+] Модуль " + moduleName + " найден по адресу: " + moduleBase);
    
    // Ищем функцию внутри модуля
    var funcPtr = Module.findExportByName(moduleName, funcName);

    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function (args) {
                // args[0] - OPENVPN_SERVER *s
                // args[1] - void *data (указатель на данные пакета)
                // args[2] - UINT size (размер данных)

                var size = args[2].toInt32();
                console.log("\n[*] Перехвачен вызов OvsProceccRecvPacket!");
                console.log("    Размер пакета: " + size);

                // Дамп первых 16 байт пакета в консоль для проверки
                if (size > 0) {
                    console.log("    Данные (HEX): " + hexdump(args[1], { length: 16 }));
                }
            }
        });
        console.log("[+] Hook успешно установлен!");
    } else {
        console.log("[-] Ошибка: Функция " + funcName + " не найдена в экспорте " + moduleName);
    }
} else {
    console.log("[-] Ошибка: Модуль " + moduleName + " не загружен. Запусти сервер!");
}
*/