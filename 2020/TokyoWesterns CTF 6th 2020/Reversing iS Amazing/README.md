First open the binary in Ghidra and rename the variables.
And you will get something like the following:

![ghidra-decompiled-rsa](./ghidra.png)

We quickly see the target `Correct!`, but simply patching the `memcmp` to return `0` will not work, as the flag is the input that lead to `Correct!`.

The first argument of `memcmp` is our (encrypted) input and the second argument is the target data (i.e. what our input should encrypt to).

Target data and the key used is hardcoded in the binary. They are fairly easy to extract, but the data could as well be the result of some complex computation (e.g. if the binary was obfuscated).

Idea:
 * Hook `RSA_private_encrypt` and save argument 4 (the rsa key)
 * Hook `memcmp` and call `RSA_public_decrypt` with argument 2 and the above key

frida script:

```js
let rsaKey = null,
    guessPtr = null;

const dump = (name, data) => console.log(`=== ${name} ===\n${hexdump(data)}\n===`);

Interceptor.attach(Module.findExportByName(null, 'RSA_private_encrypt'), {
    onEnter: function (args) {
        console.log('input len.:', args[0]);
        console.log('input.....:', args[1].readCString());
        console.log('output ptr:', args[2]); guessPtr = args[2];
        console.log('key.......:', args[3]); rsaKey = args[3];
        // dump("RSA KEY", rsaKey);
        console.log('padding...:', args[4]);
    },
    onLeave: function (retval) {
        console.log(`Size of signature = ${retval}`);  // 0x80
    }
});

const RSA_public_decrypt = new NativeFunction(Module.findExportByName(null, 'RSA_public_decrypt'), 'int', ['int', 'pointer', 'pointer', 'pointer', 'int']);

Interceptor.attach(Module.findExportByName(null, 'memcmp'), {
    onEnter: function (args) {
        this.str = `memcmp(${args[0]}, ${args[1]})`;
        // assert args[0] == guessPtr

        const x = Memory.alloc(0x80);
        RSA_public_decrypt(0x80, args[1], x, rsaKey, 1);
        dump("Flag", x);
    },
    onLeave: function (retval) {
        console.log(`${this.str} = ${retval}`)
        // retval.replace(ptr(0x0));  // this will make it print "Correct"
    }
});
```

Command:

```bash
frida -f ./rsa --no-pause --runtime=v8 -l ./crack.js "TWCTF{*****************************}"
```
