// Xrefs.java — 列出所有引用某位址的地方(及所屬函數)
// 用法: -postScript Xrefs.java <輸出檔> 0x00c2d2b8
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class Xrefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(a[0]));
        for (int i = 1; i < a.length; i++) {
            long v = Long.parseLong(a[i].replace("0x", ""), 16);
            Address target = toAddr(v);
            pw.println("==== xrefs to " + target + " ====");
            ReferenceIterator ri =
                currentProgram.getReferenceManager().getReferencesTo(target);
            int n = 0;
            while (ri.hasNext()) {
                Reference r = ri.next();
                Address from = r.getFromAddress();
                Function fn = getFunctionContaining(from);
                pw.println(from + (fn != null
                    ? "  FUNC " + fn.getEntryPoint() + " " + fn.getName()
                    : "  (no func)") + "  [" + r.getReferenceType() + "]");
                n++;
            }
            pw.println("total " + n);
        }
        pw.close();
        println("Xrefs 寫檔完成 -> " + a[0]);
    }
}
