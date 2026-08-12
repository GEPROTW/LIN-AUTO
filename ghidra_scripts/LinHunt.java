// LinHunt.java — 找關鍵字串 → 交叉引用 → 所屬函數
// 用法: analyzeHeadless ... -postScript LinHunt.java "loc x:%d y:%d" "accuseAttack" ...
// 無參數時用預設關鍵字串清單。
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class LinHunt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] needles = getScriptArgs();
        if (needles == null || needles.length == 0) {
            needles = new String[] {
                "loc x:%d y:%d",
                "location (%d, %d)",
                "Setting attack spell target to",
                "Setting beneficiary spell target to",
                "accuseAttack",
                "accusePoisonMove",
                "Target Alignment =",
            };
        }
        Memory mem = currentProgram.getMemory();
        Address min = currentProgram.getMinAddress();
        for (String s : needles) {
            println("==== \"" + s + "\" ====");
            byte[] pat = s.getBytes("US-ASCII");
            Address start = min;
            int strCount = 0;
            while (strCount < 8) {
                Address hit = mem.findBytes(start, pat, null, true, monitor);
                if (hit == null) break;
                strCount++;
                println("  str @ " + hit);
                ReferenceIterator ri =
                    currentProgram.getReferenceManager().getReferencesTo(hit);
                int rc = 0;
                while (ri.hasNext() && rc < 20) {
                    Reference r = ri.next();
                    Address from = r.getFromAddress();
                    Function fn = getFunctionContaining(from);
                    String fs = (fn != null)
                        ? ("  in FUNC " + fn.getEntryPoint() + " " + fn.getName())
                        : "  (no func)";
                    println("     xref " + from + fs);
                    rc++;
                }
                if (rc == 0) println("     (no direct xref)");
                start = hit.add(1);
            }
            if (strCount == 0) println("  (字串未找到)");
        }
        println("==== LinHunt done ====");
    }
}
