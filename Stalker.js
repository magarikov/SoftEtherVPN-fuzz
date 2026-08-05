
/*
Данный скрипт предназначен для сбора покрытия кода при фаззинге.
С помощью Stalker мы получаем адреса уникальных базовых блоков, которые 
были пройдены между началом и концом функции OvsProceccRecvPacket. 
Так как простой подсчет базовых блоков является немного устаревшим,
будем исполльзовать подсчет уникальных переходов (edges) между базовыми блоками.
Формула подсчета уникальных переходов (edges) взята из AFL: (Prev_PC >> 1) ^ Cur_PC
Адреса приводятся к относительному виду (чтобы при перезагрузке сервера не терять накопленную информацию),
затем проверяется, встречались ли они ранее, и если нет, то сохраняем их в БД (edges.json),
вместе с мутацией, которая вызвала новое покрытие.
*/

function processCoverage(stalkerEvents, curMutationPath, dbPath, module) {
    if (!stalkerEvents || stalkerEvents.length < 2) {
        return false;
    }

    // load or create the JSON database
    let db = [];
    try {
        let file = new File(dbPath, "r");
        let rawData = file.readText();
        file.close();

        db = JSON.parse(rawData);
    } catch (err) {
        console.log(`ERROR: cannot read ${dbPath}: ${err.message}.`);
    }

    // временное множество set для хранения известных edges
    let knownEdges = new Set();
    for (const record of db) {
        if (Array.isArray(record.edges)) {
            for (const edge of record.edges) {
                knownEdges.add(edge);
            }
        }
    }

    // Считаем XOR (Edge ID) для текущего запуска
    let currentPacketEdges = [];
    let newEdges = [];

    for (let i = 0; i < stalkerEvents.length - 1; i++) {
        // Извлекаем NativePointer начальных адресов текущего и следующего блоков
        let prevPtr = stalkerEvents[i][0];
        let curPtr = stalkerEvents[i + 1][0];

        // Переводим NativePointer в BigInt для безопасной работы с 64-битными адресами
        let prevAddr = BigInt(prevPtr.toString());
        let curAddr = BigInt(curPtr.toString());

        // делаем адреса относительными, а не абсолютными (чтоб не менялись каждый раз)
        var moduleBaseInt = BigInt(module.base.toString());
        prevAddr = BigInt(prevPtr.toString()) - moduleBaseInt;
        curAddr = BigInt(curPtr.toString()) - moduleBaseInt;

        // Формула AFL: (Prev_PC >> 1) ^ Cur_PC
        let edgeId = ((prevAddr >> 1n) ^ curAddr).toString(16); // Сохраняем как HEX-строку

        currentPacketEdges.push(edgeId);

        // Проверяем, встречалось ли это ребро ранее
        if (!knownEdges.has(edgeId)) {
            newEdges.push(edgeId);
            knownEdges.add(edgeId); // Добавляем в локальный сет, чтобы не дублировать внутри одного пакета
        }
    }

    // Если найдены новые переходы — сохраняем запись в БД
    if (newEdges.length > 0) {
        let file = new File(curMutationPath, "r");
        let mutationStr = file.readText();
        file.close();
        let mutationArray = JSON.parse(mutationStr);
        const newRecord = {
            edges: currentPacketEdges,
            curMutation: mutationArray,
            error: "",
            nextMutations: []
        };

        db.push(newRecord);

        // Записываем обновленную БД обратно в JSON-файл
        try {
            let file = new File(dbPath, "w");
            file.write(JSON.stringify(db, null, 2));
            file.close();

            console.log(`New edges found: ${newEdges.length}. Saved to ${dbPath}`);
        } catch (err) {
            console.error(`ERROR: cannot write to ${dbPath}:`, err.message);
        }

        return true; // Покрытие увеличилось
    }

    return false; // Новых путей не найдено
}


// configure Stalker to follow each BB
const stalker_event_config = {
    call: false,
    ret: false,
    exec: false,
    block: false, // generates event every time, when see new block (can generate multiple events for one block)
    compile: true, // same as block, but generates event only once 
};

var moduleName = "libcedar.so";
var module = Process.findModuleByName(moduleName);

// the function where coverage collection should start 
const funcName = 'OvsProceccRecvPacket';
var funcPtr = module.findExportByName(funcName);

let stalker_events = undefined;
let gc_counter = 0;

Process.enumerateModules().forEach(function (m) {
    if (m.name !== moduleName) {
        Stalker.exclude(m);
    }
})

Interceptor.attach(funcPtr, {
    onEnter: function(args) {
        Stalker.follow({
            events: stalker_event_config,
            onReceive: function (events) {
                stalker_events = Stalker.parse(events, {
                    stringify: false, // преобразование сырых адресов в строки
                    annotate: false} // добавлять тип события 
                );
            }
        })
    },
    onLeave: function() {
        Stalker.unfollow();
        Stalker.flush();
        if (gc_counter > 300) {
            Stalker.garbageCollect();
            gc_counter = 0;
        }
        gc_counter++;

        // at this point, stalker_events should contain the executed basic 
        // blocks in the following form:
        // [["START_ADDR", "END_ADDR"], ["START_ADDR2", "END_ADDR2"], ...]

        // the collected coverage can be returned to the fuzzer
        let curMutationPath = "/mnt/c/Users/magar/Desktop/1000101/NIR/data/cur_mutation.json";
        let dbPath = "/mnt/c/Users/magar/Desktop/1000101/NIR/data/edges.json"
        processCoverage(stalker_events, curMutationPath, dbPath, module);
    }
});