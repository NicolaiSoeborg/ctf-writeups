# The Vault

The challenge is a simple HTML file with a keypad that allows you to input 4 digit pin.
The file loads `main.js` and calls `Module.ccall('validate')` to check the pin.

Upon beautifying the JS we see that it calls `run()` which in turns runs:

```javascript
preRun();
initRuntime();  // => __wasm_call_ctors => Module["asm"]["h"]
preMain();
callMain(args);  // => main => Module["asm"]["m"]
postRun()
```

We also note the following "library" mapping in `main.js`:

```javascript
var asmLibraryArg = {
    "e": banner,
    "a": _emscripten_resize_heap,
    "b": fail,
    "d": get_password,
    "c": win
};
```

The WASM binary format can be turned into "WebAssembly Text (`WAT`)" using e.g. https://webassembly.github.io/wabt/demo/wasm2wat/ and then we find the JS-imports in the top and the wasm-exports near the end of the file:

```lisp
(module
  ; ...
  (import "a" "a" (func $a.a (type $t1)))  ; _emscripten_resize_heap
  (import "a" "b" (func $a.b (type $t2)))  ; fail
  (import "a" "c" (func $a.c (type $t3)))  ; win
  (import "a" "d" (func $a.d (type $t0)))  ; get_password
  (import "a" "e" (func $a.e (type $t2)))  ; banner

  ; __wasm_call_ctors
  (func $h (type $t2)
    nop)

  ; main
  (func $m (type $t4) (param $p0 i32) (param $p1 i32) (result i32)
    call $a.e
    i32.const 0)

  ; ...
  (export "h" (func $h))
  (export "m" (func $m))
  (export "n" (func $n))
)
```

During startup all the `.wasm` file does is to print this super awesome banner:

<p style="font-weight: bold; font-size: 50px;color: red; text-shadow: 3px 3px 0 rgb(217,31,38) , 6px 6px 0 rgb(226,91,14) , 9px 9px 0 rgb(245,221,8) , 12px 12px 0 rgb(5,148,68) , 15px 15px 0 rgb(2,135,206) , 18px 18px 0 rgb(4,77,145) , 21px 21px 0 rgb(42,21,113)">
    WASM VAULT v0.1
</p>

## Initial idea

The PIN is a maximum of 4 digit and checked locally, right? So it should be super easy to bruteforce;

 * Patch the `fail` function to remove all logic (and skip blocking `alert()`)
 * Run the following in the browser console:

```javascript
for (let i = 0; i < 10_000; i++) {
    document.getElementById('password').value = String(i).padStart(4, '0');
    Module.ccall('validate');
}
```

... aaand it didn't work. Maybe I shouldn't pad with `0` ? Maybe I can't do multiple failing `validate` calls?

I had a lot of uncertainties and assumptions I needed to test, but the biggest takeaway that this is not the right idea, is that it would be way too easy to do a `for` loop and just bruteforce the PIN.

## Let the reversing begin

In `main.js` we see that `validate` maps to `$n` in the wasm file:

```lisp
(func $n (type $t2)
    (local $l0 i32) (local $l1 i32) (local $l2 i32) (local $l3 i32) (local $l4 i32)
    global.get $g0  ; SP?
    i32.const 32
    i32.sub
    local.tee $l0
    global.set $g0
    call $a.d      ; get_password
    local.set $l1  ; $l1 = password
    local.get $l0
    i32.const 1720
    i32.load16_u
    i32.store16 offset=24
    local.get $l0
    i32.const 1712
    i64.load
    i64.store offset=16
    local.get $l0
    i32.const 1704
    i64.load
    i64.store offset=8
    local.get $l0
    i32.const 1696
    i64.load
    i64.store
    block $B0
      block $B1
        local.get $l1
        call $f7       ; strlen(password) ?
        i32.const 4
        i32.ne
        br_if $B1
        local.get $l1  ; $l1 = password
        i32.load8_u
        i32.const 112  ; 'p'
        i32.ne
        br_if $B1
        local.get $l1  ; $l1 = password
        i32.load8_u offset=1
        i32.const 51   ; '3'
        i32.ne
        br_if $B1
        local.get $l1  ; $l1 = password
        i32.load8_u offset=2
        i32.const 107  ; 'k'
        i32.ne
        br_if $B1
        local.get $l1  ; $l1 = password
        i32.load8_u offset=3
        i32.const 48   ; '0'
        i32.ne
        br_if $B1
        i32.const 22
        local.set $l3
        local.get $l0
        local.set $l4
        loop $L2
          local.get $l4
          local.get $l1
          local.get $l2
          i32.const 3
          i32.and
          i32.add
          i32.load8_u
          local.get $l3
          i32.xor
          i32.store8
          local.get $l0
          local.get $l2
          i32.const 1
          i32.add
          local.tee $l2
          i32.add
          local.tee $l4
          i32.load8_u
          local.tee $l3
          br_if $L2
        end
        local.get $l0
        call $a.c  ; win
        br $B0
      end
      call $a.b    ; fail
    end
    local.get $l0
    i32.const 32
    i32.add
    global.set $g0
)
```

I did not get far before I saw `p3k0`... Not the PIN I was expecting, but it worked:

```javascript
document.getElementById('password').value = "p3k0";
Module.ccall('validate');
// You win! Here is you flag: flag{w45m_w4sm_wa5m_wasm}
```
