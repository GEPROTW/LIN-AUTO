// DecompAt.java — 反編譯指定位址所屬函數, 直接寫檔(避免 log 多行被截)
// 用法: -postScript DecompAt.java <輸出檔> 0x0040a790 0x00405a20 ...
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args[0];
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (int i = 1; i < args.length; i++) {
            long v = Long.parseLong(args[i].replace("0x", ""), 16);
            Address addr = toAddr(v);
            Function fn = getFunctionContaining(addr);
            if (fn == null) fn = getFunctionAt(addr);
            if (fn == null) {
                pw.println("// 無函數 @ " + args[i]);
                continue;
            }
            pw.println("//======== " + fn.getName() + " @ " + fn.getEntryPoint()
                    + "  (size " + fn.getBody().getNumAddresses() + ") ========");
            DecompileResults res = di.decompileFunction(fn, 60, monitor);
            if (res != null && res.decompileCompleted()) {
                pw.println(res.getDecompiledFunction().getC());
            } else {
                pw.println("// 反編譯失敗: " + (res != null ? res.getErrorMessage() : "null"));
            }
            pw.flush();
        }
        pw.println("//======== DecompAt done ========");
        pw.close();
        println("DecompAt 寫檔完成 -> " + outPath);
    }
}
