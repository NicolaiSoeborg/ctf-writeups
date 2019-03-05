import frida
import sys
import threading

device = frida.get_usb_device()
device.enable_spawn_gating()
# print('Enabled spawn gating')
target = sys.argv[1] or 'process'

try:
    if target == 'process':
        raise frida.ProcessNotFoundError
    proc = device.get_process(target)
    print(f'Killing {target}')
    device.kill(proc.pid)
except frida.ProcessNotFoundError:
    pass

pending = []
event = threading.Event()

def on_message(message, data):
    print('on_message:', message, data)

def on_spawned(spawn):
    pending.append(spawn)
    event.set()
device.on('spawn-added', on_spawned)

for spawn in device.enumerate_pending_spawn():
    # remove ("old") any pending:
    print('Resuming:', spawn)
    device.resume(spawn.pid)

#if target != 'process':
#    device.spawn([target])
while True:
    while len(pending) == 0:
        print(f'Waiting for {target} to spawn')
        event.wait()
        event.clear()

    spawn = pending.pop()
    assert spawn.identifier is not None, f'WAT: {spawn}'
    print(f"Found process {spawn.identifier}")
    if target in [spawn.identifier, 'process']:
        break
    else:
        device.resume(spawn.pid)

session = device.attach(spawn.pid)
script = session.create_script("""\
"use strict";

if (!Java.available) console.log("No Java... WAT");

(function () {
rpc.exports = {
    init() {
        Java.performNow(function x() {

            /*Java.use('org.json.JSONObject').$init.overload('java.lang.String').implementation = function (arg) {
                var result = this.$init(arg);
                console.log(arg);
                return result;
            }*/

            Java.use('java.net.URL').$init.overload('java.lang.String').implementation = function (s) {
                var result = this.$init(s);
                console.log("URL: " + s);
                return result;
            }

            /*Java.use('java.lang.String').getBytes.overload().implementation = function () {
                var result = this.getBytes();
                console.log(this);
                return result;
            }*/

        })
    }
};
}).call(this);

console.log("SCRIPT FULLY LOADED");
""")


script.on('message', on_message)
script.load()  # inject script
script.exports.init()

device.resume(spawn.pid)

for spawn in device.enumerate_pending_spawn():
    print('Resuming:', spawn)
    device.resume(spawn.pid)
device.disable_spawn_gating()

print("Waiting for injection output...")
sys.stdin.read()  # read from stdin to keep script running
