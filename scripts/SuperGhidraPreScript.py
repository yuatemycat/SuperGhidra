# SuperGhidra Auto-Analysis PreScript (Python)
# Prevents the pathological repairDamagedLocations CPU cascade
# @category SuperGhidra

from ghidra.program.model.listing import Program

def run():
    print("[SuperGhidra] Configuring optimized headless analysis options...")
    options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
    settings = {
        "Non-Returning Functions - Discovered": "false",
        "Repair Flow Damage": "false",
        "Non-Returning Functions - Known": "true",
        "Disassemble Entry Points": "true",
        "Decompiler Switch Analysis": "true",
        "Demangler GNU": "true",
        "Demangler Microsoft": "true",
        "Demangler Rust": "true",
        "Demangler Swift": "true",
        "Stack": "true",
        "Subroutine References": "false",
        "Call-Fixup Installer": "true",
        "Variadic Function Signature Override": "false",
        "Aggressive Instruction Finder": "false",
        "ARM Aggressive Instruction Finder": "false",
        "Function ID": "true",
        "ASCII Strings": "true",
    }
    for k, v in settings.items():
        setAnalysisOption(currentProgram, k, v)
    print("[SuperGhidra] Successfully disabled FindNoReturnFunctionsAnalyzer cascade guard.")
    print("[SuperGhidra] Lean analyzer pipeline active.")

run()
