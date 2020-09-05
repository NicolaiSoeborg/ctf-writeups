# Android

This challenge was part of Google CTF 2020.

Based on [some of the other write-ups on CTFTime](https://ctftime.org/task/12815) I wanted to show another approach, as people had problems decompiling with [jadx](https://github.com/skylot/jadx).

You want to build the newest from git (some nice changes between last release and current `master` is the flag: `--deobf-parse-kotlin-metadata`).

Then you probably want to use the following commands for *most* apks:

```bash
$ jadx --threads-count 1 --show-bad-code --deobf --deobf-min 2 --deobf-use-sourcename --deobf-parse-kotlin-metadata ./reverse.apk
INFO  - loading ...
INFO  - processing ...
INFO  - done
```

Some commends:
 * `--threads-count 1` -- I've seen race-conditions in jadx due to concurrency
 * `--show-bad-code` -- Even if jadx can't decompile correctly, show the result
 * `--deobf` -- Tell jadx to prepare for the worst (i.e. class name with esoteric letters, or everything called `a.a(a)`, etc)
 * `--deobf-min 2` -- With the above flag, jadx treat `dk.io.something` as having a obfuscated name (b/c it is < 3 chars long)
 * `--deobf-use-sourcename` -- Trust "sourcename", this mostly works, but if the output is completely screwed then remove this flag
 * `--deobf-parse-kotlin-metadata` -- Same as above

In `reverse/sources/com/google/ctf/sandbox/` we find the following files:

```
BuildConfig.java
C0006R.java
C0007.java
```

The `C<d><d><d><d>.java` file is the first deobfuscated class (we see jadx has renamed it from `com.google.ctf.sandbox.ő` to `com.google.ctf.sandbox.C0007`)
And note the "resource file", `C0006R.java`, contains the method `m0` renamed from `ő`.  We can now clearly see the difference due to the `--deobf` flag!

```java
    /* renamed from: ő */
    public static long[] m0(long a, long b) {
        if (a == 0) {
            return new long[]{0, 1};
        }
        long[] r = m0(b % a, a);
        return new long[]{r[1] - ((b / a) * r[0]), r[0]};
    }
```

```java
/* renamed from: com.google.ctf.sandbox.ő */
public class C0007 extends Activity {
    /* renamed from: class  reason: not valid java name */
    long[] f8class;

    /* renamed from: ő */
    int f6;

    /* renamed from: ő */
    long[] f7;
```

In the constructor of `C0007` we see this suspicious array:

```java
this.f8class = new long[]{40999019, 2789358025L, 656272715, 18374979, 3237618335L, 1762529471, 685548119, 382114257, 1436905469, 2126016673, 3318315423L, 797150821};
```

Following by some logic and then:

```java
C0007.this.f6 = 0;
// [...]
if (((C0006R.m0(C0007.this.f7[C0007.this.f6], 4294967296L)[0] % 4294967296L) + 4294967296L) % 4294967296L != C0007.this.f8class[C0007.this.f6]) {
    textView.setText("❌");
    return;
}
C0007.this.f6++;
if (C0007.this.f6 >= C0007.this.f7.length) {
    textView.setText("🚩");
    return;
}
```

Lets clean it up:

```java
int i = 0;
// [...]
if (m0(f7[i], 4294967296L)[0] % 4294967296L != f8class[i]) {
    textView.setText("❌");
    return;
}
i++;
if (i >= 12) {
    textView.setText("🚩");
    return;
}
```

So we need to solve a bunch of similar equations:

 * `m0(?, 0x100000000)[0] = 40999019`
 * `m0(?, 0x100000000)[0] = 2789358025`
 * `m0(?, 0x100000000)[0] = 656272715`
 * `m0(?, 0x100000000)[0] = 18374979`
 * `m0(?, 0x100000000)[0] = 3237618335`
 * `m0(?, 0x100000000)[0] = 1762529471`
 * `m0(?, 0x100000000)[0] = 685548119`
 * `m0(?, 0x100000000)[0] = 382114257`
 * `m0(?, 0x100000000)[0] = 1436905469`
 * `m0(?, 0x100000000)[0] = 2126016673`
 * `m0(?, 0x100000000)[0] = 3318315423`
 * `m0(?, 0x100000000)[0] = 797150821`

We know each `?` is a number between `0..2**32`, so we can find all possible solutions in `2**32 \times m0`-operations:

```java
import java.util.stream.LongStream;

public class Bruteforce
{
    public static void main(final String[] array) {
        LongStream.rangeClosed(1L, 4294967296L).parallel().forEach(Bruteforce::test);
    }

    private static void test(final long n) {
        final long n2 = (m0(n, 4294967296L)[0] % 4294967296L + 4294967296L) % 4294967296L;
        if (n2 == 40999019L || n2 == 2789358025L || n2 == 656272715L || n2 == 18374979L || n2 == 3237618335L || n2 == 1762529471L || n2 == 685548119L || n2 == 382114257L || n2 == 1436905469L || n2 == 2126016673L || n2 == 3318315423L || n2 == 797150821L) {
            System.out.println(String.format("ans for %d is %d", n2, n));
        }
    }

    public static long[] m0(final long n, final long n2) { // egcd
        if (n == 0L) {
            return new long[] { 0L, 1L };
        }
        final long[] tmp = m0(n2 % n, n);
        return new long[] { tmp[1] - n2 / n * tmp[0], tmp[0] };
    }
}
```

```bash
javac Bruteforce.java
time java Bruteforce
ans for 18374979 is 106116784
ans for 18374979 is 212233568
ans for 685548119 is 1600350567
ans for 656272715 is 1601057891
ans for 2789358025 is 1601515641
ans for 3318315423 is 1630757471
ans for 382114257 is 879255345
ans for 1762529471 is 879583039
ans for 18374979 is 424467136
ans for 40999019 is 1758103648
ans for 382114257 is 1758510690
ans for 797150821 is 2099344237
ans for 1436905469 is 1818191189
ans for 18374979 is 2200542040
ans for 18374979 is 1885680491
ans for 2126016673 is 1919251297
ans for 3237618335 is 1966111071
ans for 40999019 is 2068206659
ans for 40999019 is 3026535472
ans for 685548119 is 3200701134
ans for 656272715 is 3202115782
ans for 18374979 is 3247754668
ans for 3318315423 is 3261514942
ans for 18374979 is 3771360982
ans for 40999019 is 3660751384
ans for 382114257 is 3517021380
ans for 40999019 is 3977859340
ans for 3237618335 is 3932222142
ans for 40999019 is 4136413318
ans for 797150821 is 4198688474

real	6m12.444s
user	14m10.893s
sys		0m2.036s
```

Finally we can reconstruct the flag:

```python
def print_if_ascii(n):
    try:
        s = bytes.fromhex(hex(n)[2:].zfill(8))[::-1].decode()
        print(s, end='')
    except: pass

# Solutions for 40999019
print_if_ascii(1758103648)
print_if_ascii(2068206659)
print_if_ascii(3026535472)
print_if_ascii(3660751384)
print_if_ascii(3977859340)
print_if_ascii(4136413318)

# Solution for 2789358025
print_if_ascii(1601515641)

# Solutions for 656272715
print_if_ascii(1601057891)
print_if_ascii(3202115782)

# Solutions for 18374979
print_if_ascii(106116784)
print_if_ascii(212233568)
print_if_ascii(424467136)
print_if_ascii(2200542040)
print_if_ascii(1885680491)
print_if_ascii(3247754668)
print_if_ascii(3771360982)

# Solutions for 3237618335
print_if_ascii(1966111071)
print_if_ascii(3932222142)

# Solution for 1762529471
print_if_ascii(879583039)

# Solutions for 685548119
print_if_ascii(1600350567)
print_if_ascii(3200701134)

# Solutions for 382114257
print_if_ascii(879255345)
print_if_ascii(1758510690)
print_if_ascii(3517021380)

# Solution for 1436905469
print_if_ascii(1818191189)

# Solution for 2126016673
print_if_ascii(1919251297)

# Solutions for 3318315423
print_if_ascii(1630757471)
print_if_ascii(3261514942)

# Solutions for 797150821
print_if_ascii(2099344237)
print_if_ascii(4198688474)
```

Output: `CTF{y0u_c4n_k3ep_y0u?_m4gic_1_h4Ue_laser_b3ams!}`
