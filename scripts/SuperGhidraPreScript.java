// SuperGhidra Auto-Analysis PreScript (Java)
// Prevents the pathological repairDamagedLocations CPU cascade
// @category SuperGhidra

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class SuperGhidraPreScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("[SuperGhidra] Configuring optimized headless analysis options...");
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);

        setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
        setAnalysisOption(currentProgram, "Repair Flow Damage", "false");
        setAnalysisOption(currentProgram, "Non-Returning Functions - Known", "true");
        setAnalysisOption(currentProgram, "Disassemble Entry Points", "true");
        setAnalysisOption(currentProgram, "Decompiler Switch Analysis", "true");
        setAnalysisOption(currentProgram, "Demangler GNU", "true");
        setAnalysisOption(currentProgram, "Demangler Microsoft", "true");
        setAnalysisOption(currentProgram, "Demangler Rust", "true");
        setAnalysisOption(currentProgram, "Demangler Swift", "true");
        setAnalysisOption(currentProgram, "Stack", "true");
        setAnalysisOption(currentProgram, "Subroutine References", "false");
        setAnalysisOption(currentProgram, "Call-Fixup Installer", "true");
        setAnalysisOption(currentProgram, "Variadic Function Signature Override", "false");
        setAnalysisOption(currentProgram, "Aggressive Instruction Finder", "false");
        setAnalysisOption(currentProgram, "ARM Aggressive Instruction Finder", "false");
        setAnalysisOption(currentProgram, "Function ID", "true");
        setAnalysisOption(currentProgram, "ASCII Strings", "true");

        println("[SuperGhidra] Successfully disabled FindNoReturnFunctionsAnalyzer cascade guard.");
        println("[SuperGhidra] Lean analyzer pipeline active.");
    }
}
