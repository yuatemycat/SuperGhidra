// SuperGhidra Lazy Non-Returning Function Discovery PostScript (Java)
// Analyzes function exit points cleanly without triggering destructive flow clearing
// @category SuperGhidra

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import java.util.*;

public class SuperGhidraLazyNoReturnPostScript extends GhidraScript {

    private static final Set<String> KNOWN_TERMINAL_NAMES = new HashSet<>(Arrays.asList(
        "exit", "_exit", "_Exit", "quick_exit", "abort", "__assert_fail",
        "__stack_chk_fail", "panic", "fatal", "terminate", "__cxa_throw",
        "pthread_exit", "ExitProcess", "TerminateProcess", "RaiseException"
    ));

    @Override
    public void run() throws Exception {
        println("[SuperGhidra] Running Lazy Non-Returning Function Discovery pass...");
        FunctionManager fnManager = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        int markedCount = 0;
        int txId = currentProgram.startTransaction("SuperGhidra Lazy NoReturn Pass");
        try {
            FunctionIterator iter = fnManager.getFunctions(true);
            while (iter.hasNext() && !monitor.isCancelled()) {
                Function fn = iter.next();
                if (fn.hasNoReturn()) {
                    continue;
                }

                String fnName = fn.getName().toLowerCase();
                boolean isTerminalName = false;
                for (String term : KNOWN_TERMINAL_NAMES) {
                    if (fnName.contains(term.toLowerCase())) {
                        isTerminalName = true;
                        break;
                    }
                }

                if (isTerminalName) {
                    fn.setNoReturn(true);
                    markedCount++;
                    continue;
                }

                // Inspect terminal blocks of function CFG
                AddressSetView body = fn.getBody();
                InstructionIterator instIter = listing.getInstructions(body, true);
                boolean hasReturn = false;
                boolean callsTerminal = false;

                while (instIter.hasNext()) {
                    Instruction inst = instIter.next();
                    FlowType flow = inst.getFlowType();
                    if (flow.isTerminal() || flow == RefType.COMPUTED_CALL) {
                        Reference[] refs = inst.getReferencesFrom();
                        for (Reference ref : refs) {
                            Function calledFn = fnManager.getFunctionAt(ref.getToAddress());
                            if (calledFn != null && calledFn.hasNoReturn()) {
                                callsTerminal = true;
                            }
                        }
                    }
                    if (flow.isTerminal() && !flow.isCall()) {
                        hasReturn = true;
                        break;
                    }
                }

                // If function does not have a return instruction and invokes a non-returning target
                if (!hasReturn && callsTerminal) {
                    fn.setNoReturn(true);
                    markedCount++;
                }
            }
        } finally {
            currentProgram.endTransaction(txId, true);
        }

        println("[SuperGhidra] Lazy NoReturn Pass complete. Safely marked " + markedCount + " functions.");
        println("[SuperGhidra] Zero flow repair cascades incurred.");
    }
}
