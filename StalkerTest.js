

function AddToDB(prevAddr, nextAddr) {

}

// configure Stalker to follow each BB
const stalker_event_config = {
    call: false,
    ret: false,
    exec: false,
    block: false, // generate event every time, when see new block (can generate multiple events for one block)
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
        for (var i = 0; i < stalker_events.length - 1; i++) {
            AddToDB(stalker_events[i][0], stalker_events[i + 1][0]);
        }
        // the collected coverage can be returned to the fuzzer

        //console.log('\n')
        //send(stalker_events);
    }
});