// DisasmAt.java — 反組譯指定函數(看暫存器/全域載入)
// 用法: -postScript DisasmAt.java <輸出檔> 0x0040d180 ...
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class DisasmAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(a[0]));
        for (int i = 1; i < a.length; i++) {
            long v = Long.parseLong(a[i].replace("0x", ""), 16);
            Address addr = toAddr(v);
            Function fn = getFunctionContaining(addr);
            if (fn == null) fn = getFunctionAt(addr);
            if (fn == null) { pw.println("// 無函數 @ " + a[i]); continue; }
            pw.println("//==== " + fn.getName() + " @ " + fn.getEntryPoint() + " ====");
            InstructionIterator it =
                currentProgram.getListing().getInstructions(fn.getBody(), true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                pw.println(ins.getAddress() + ":  " + ins.toString());
            }
        }
        pw.close();
        println("DisasmAt 寫檔完成 -> " + a[0]);
    }
}
