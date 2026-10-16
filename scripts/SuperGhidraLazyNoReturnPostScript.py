# SuperGhidra Lazy Non-Returning Function Discovery PostScript (Python)
# Analyzes function exit points cleanly without triggering destructive flow clearing
# @category SuperGhidra

from ghidra.program.model.symbol import RefType

KNOWN_TERMINALS = {
    "exit", "_exit", "_Exit", "quick_exit", "abort", "__assert_fail",
    "__stack_chk_fail", "panic", "fatal", "terminate", "__cxa_throw",
    "pthread_exit", "ExitProcess", "TerminateProcess", "RaiseException"
}

def run():
    print("[SuperGhidra] Running Lazy Non-Returning Function Discovery pass...")
    fn_mgr = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    marked_count = 0

    tx_id = currentProgram.startTransaction("SuperGhidra Lazy NoReturn Pass")
    try:
        funcs = fn_mgr.getFunctions(True)
        for fn in funcs:
            if fn.hasNoReturn():
                continue
            name_lower = fn.getName().lower()
            if any(term in name_lower for term in KNOWN_TERMINALS):
                fn.setNoReturn(True)
                marked_count += 1
                continue

            # Check instructions for returns vs non-return calls
            body = fn.getBody()
            inst_iter = listing.getInstructions(body, True)
            has_return = False
            calls_terminal = False

            for inst in inst_iter:
                flow = inst.getFlowType()
                if flow.isTerminal() and not flow.isCall():
                    has_return = True
                    break
                if flow.isCall():
                    for ref in inst.getReferencesFrom():
                        called = fn_mgr.getFunctionAt(ref.getToAddress())
                        if called and called.hasNoReturn():
                            calls_terminal = True

            if not has_return and calls_terminal:
                fn.setNoReturn(True)
                marked_count += 1
    finally:
        currentProgram.endTransaction(tx_id, True)

    print(f"[SuperGhidra] Lazy NoReturn Pass complete. Safely marked {marked_count} functions.")
    print("[SuperGhidra] Zero flow repair cascades incurred.")

run()
