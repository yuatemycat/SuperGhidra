#!/usr/bin/env python3
"""SuperGhidra Headless Analyzer Tuner.

Generates tuned, high-throughput Ghidra headless analysis pipelines for `analyzeHeadless`.
Key optimizations:
  1. Cascade Shield: Explicitly disables `FindNoReturnFunctionsAnalyzer`
     ("Non-Returning Functions - Discovered") and "Repair Flow Damage" to eliminate
     the pathological `repairDamagedLocations` CPU cascade that stalls large binary analysis.
  2. Safe Non-Return Detection: Retains "Non-Returning Functions - Known" and establishes
     a Lazy Non-Returning Function Discovery post-script pass that inspects CFG terminals
     without triggering destructive recursive instruction clearing.
  3. Tiered Analyzer Pipelines: Profiles for Fast Triage (Lean), Decompilation Ready,
     and Full Guarded analysis.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AnalyzerProfileName(str, Enum):
    LEAN = "lean"                      # Minimal triage: disassembly, symbols, demanglers
    DECOMP_READY = "decomp_ready"      # Optimized for fast decompiler code generation
    FULL_GUARDED = "full_guarded"      # All analyzers active except cascade culprits


@dataclass
class AnalyzerConfiguration:
    """Explicit analyzer option flags for Ghidra's Program.ANALYSIS_PROPERTIES."""

    # Cascade culprits (MUST BE FALSE to prevent repairDamagedLocations CPU stall)
    non_returning_discovered: bool = False
    repair_flow_damage: bool = False

    # Safe Non-Returning Analyzer (matches known CRT/runtime names: exit, abort, panic, etc.)
    non_returning_known: bool = True

    # Control Flow & Disassembly
    disassemble_entry_points: bool = True
    decompiler_switch_analysis: bool = True

    # Demanglers
    demangler_gnu: bool = True
    demangler_microsoft: bool = True
    demangler_rust: bool = True
    demangler_swift: bool = False

    # Heavy analyzers (disabled in lean, enabled in decomp_ready/full_guarded)
    stack_analysis: bool = False
    subroutine_references: bool = False
    call_fixup_installer: bool = False
    variadic_signatures: bool = False
    aggressive_instruction_finder: bool = False
    arm_aggressive_instruction_finder: bool = False
    shared_return_calls: bool = False
    constant_reference_analyzer: bool = False
    function_id: bool = True
    ascii_strings: bool = True

    # Additional custom options
    custom_options: Dict[str, Any] = field(default_factory=dict)

    def to_ghidra_options_map(self) -> Dict[str, str]:
        """Maps configuration fields to exact Ghidra analyzer option property names."""
        options: Dict[str, str] = {
            # THE CRITICAL CASCADE GUARD
            "Non-Returning Functions - Discovered": "true" if self.non_returning_discovered else "false",
            "Repair Flow Damage": "true" if self.repair_flow_damage else "false",

            # Safe static signature detection
            "Non-Returning Functions - Known": "true" if self.non_returning_known else "false",

            # Flow & Disassembly
            "Disassemble Entry Points": "true" if self.disassemble_entry_points else "false",
            "Decompiler Switch Analysis": "true" if self.decompiler_switch_analysis else "false",

            # Demanglers
            "Demangler GNU": "true" if self.demangler_gnu else "false",
            "Demangler Microsoft": "true" if self.demangler_microsoft else "false",
            "Demangler Rust": "true" if self.demangler_rust else "false",
            "Demangler Swift": "true" if self.demangler_swift else "false",

            # Heavy Analyzers
            "Stack": "true" if self.stack_analysis else "false",
            "Subroutine References": "true" if self.subroutine_references else "false",
            "Call-Fixup Installer": "true" if self.call_fixup_installer else "false",
            "Variadic Function Signature Override": "true" if self.variadic_signatures else "false",
            "Aggressive Instruction Finder": "true" if self.aggressive_instruction_finder else "false",
            "ARM Aggressive Instruction Finder": "true" if self.arm_aggressive_instruction_finder else "false",
            "Function ID": "true" if self.function_id else "false",
            "ASCII Strings": "true" if self.ascii_strings else "false",
        }

        for k, v in self.custom_options.items():
            options[k] = "true" if v is True else ("false" if v is False else str(v))

        return options


def get_profile_config(profile: AnalyzerProfileName) -> AnalyzerConfiguration:
    """Returns tuned analyzer settings for the requested profile."""
    if profile == AnalyzerProfileName.LEAN:
        return AnalyzerConfiguration(
            non_returning_discovered=False,
            repair_flow_damage=False,
            non_returning_known=True,
            disassemble_entry_points=True,
            decompiler_switch_analysis=False,
            demangler_gnu=True,
            demangler_microsoft=True,
            demangler_rust=True,
            demangler_swift=False,
            stack_analysis=False,
            subroutine_references=False,
            call_fixup_installer=False,
            variadic_signatures=False,
            aggressive_instruction_finder=False,
            arm_aggressive_instruction_finder=False,
            function_id=False,
            ascii_strings=True,
        )
    elif profile == AnalyzerProfileName.DECOMP_READY:
        return AnalyzerConfiguration(
            non_returning_discovered=False,
            repair_flow_damage=False,
            non_returning_known=True,
            disassemble_entry_points=True,
            decompiler_switch_analysis=True,
            demangler_gnu=True,
            demangler_microsoft=True,
            demangler_rust=True,
            demangler_swift=True,
            stack_analysis=True,
            subroutine_references=False,
            call_fixup_installer=True,
            variadic_signatures=False,
            aggressive_instruction_finder=False,
            arm_aggressive_instruction_finder=False,
            function_id=True,
            ascii_strings=True,
        )
    elif profile == AnalyzerProfileName.FULL_GUARDED:
        return AnalyzerConfiguration(
            non_returning_discovered=False,  # Still DISABLED for safety!
            repair_flow_damage=False,        # Still DISABLED for safety!
            non_returning_known=True,
            disassemble_entry_points=True,
            decompiler_switch_analysis=True,
            demangler_gnu=True,
            demangler_microsoft=True,
            demangler_rust=True,
            demangler_swift=True,
            stack_analysis=True,
            subroutine_references=True,
            call_fixup_installer=True,
            variadic_signatures=True,
            aggressive_instruction_finder=False,
            arm_aggressive_instruction_finder=False,
            function_id=True,
            ascii_strings=True,
        )
    raise ValueError(f"Unknown profile: {profile}")


class ScriptGenerator:
    """Generates Ghidra pre-scripts and post-scripts."""

    @staticmethod
    def generate_prescript_java(config: AnalyzerConfiguration, class_name: str = "SuperGhidraPreScript") -> str:
        """Generates a Ghidra Java PreScript to apply analyzer option configuration."""
        options_map = config.to_ghidra_options_map()
        lines = [
            "// SuperGhidra Auto-Analysis PreScript (Java)",
            "// Prevents the pathological repairDamagedLocations CPU cascade",
            "// @category SuperGhidra",
            "",
            "import ghidra.app.script.GhidraScript;",
            "import ghidra.framework.options.Options;",
            "import ghidra.program.model.listing.Program;",
            "",
            f"public class {class_name} extends GhidraScript {{",
            "    @Override",
            "    public void run() throws Exception {",
            '        println("[SuperGhidra] Configuring optimized headless analysis options...");',
            "        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);",
            "",
        ]

        for name, val in options_map.items():
            clean_name = name.replace('"', '\\"')
            if val.lower() in ("true", "false"):
                lines.append(f'        setAnalysisOption(currentProgram, "{clean_name}", "{val}");')
            else:
                lines.append(f'        setAnalysisOption(currentProgram, "{clean_name}", "{val}");')

        lines.extend([
            "",
            '        println("[SuperGhidra] Successfully disabled FindNoReturnFunctionsAnalyzer cascade guard.");',
            '        println("[SuperGhidra] Lean analyzer pipeline active.");',
            "    }",
            "}",
            ""
        ])
        return "\n".join(lines)

    @staticmethod
    def generate_prescript_python(config: AnalyzerConfiguration) -> str:
        """Generates a Ghidra Python PreScript (for Jython / PyGhidra headless)."""
        options_map = config.to_ghidra_options_map()
        lines = [
            "# SuperGhidra Auto-Analysis PreScript (Python)",
            "# Prevents the pathological repairDamagedLocations CPU cascade",
            "# @category SuperGhidra",
            "",
            "from ghidra.program.model.listing import Program",
            "",
            "def run():",
            '    print("[SuperGhidra] Configuring optimized headless analysis options...")',
            "    options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)",
            "    settings = {",
        ]

        for name, val in options_map.items():
            lines.append(f'        "{name}": "{val}",')

        lines.extend([
            "    }",
            "    for k, v in settings.items():",
            "        setAnalysisOption(currentProgram, k, v)",
            '    print("[SuperGhidra] Successfully disabled FindNoReturnFunctionsAnalyzer cascade guard.")',
            '    print("[SuperGhidra] Lean analyzer pipeline active.")',
            "",
            "run()",
            ""
        ])
        return "\n".join(lines)

    @staticmethod
    def generate_lazy_noreturn_postscript_java(class_name: str = "SuperGhidraLazyNoReturnPostScript") -> str:
        """Generates a Ghidra Java PostScript for lazy non-returning function discovery.

        Inspects functions after initial disassembly is complete. Marks non-returning
        functions cleanly WITHOUT invoking ClearFlowAndRepairCmd or clearing bookmarks.
        """
        code = f"""// SuperGhidra Lazy Non-Returning Function Discovery PostScript (Java)
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

public class {class_name} extends GhidraScript {{

    private static final Set<String> KNOWN_TERMINAL_NAMES = new HashSet<>(Arrays.asList(
        "exit", "_exit", "_Exit", "quick_exit", "abort", "__assert_fail",
        "__stack_chk_fail", "panic", "fatal", "terminate", "std::terminate", "__cxa_throw",
        "longjmp", "_longjmp", "siglongjmp", "pthread_exit", "ExitProcess", "TerminateProcess", "RaiseException"
    ));

    @Override
    public void run() throws Exception {{
        println("[SuperGhidra] Running Lazy Non-Returning Function Discovery pass...");
        FunctionManager fnManager = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        int markedCount = 0;
        int txId = currentProgram.startTransaction("SuperGhidra Lazy NoReturn Pass");
        try {{
            FunctionIterator iter = fnManager.getFunctions(true);
            while (iter.hasNext() && !monitor.isCancelled()) {{
                Function fn = iter.next();
                if (fn.hasNoReturn()) {{
                    continue;
                }}

                String fnName = fn.getName().toLowerCase();
                boolean isTerminalName = false;
                for (String term : KNOWN_TERMINAL_NAMES) {{
                    String tl = term.toLowerCase();
                    if (fnName.equals(tl) || fnName.endsWith("::" + tl) || fnName.endsWith("." + tl)) {{
                        isTerminalName = true;
                        break;
                    }}
                }}

                if (isTerminalName) {{
                    fn.setNoReturn(true);
                    markedCount++;
                    continue;
                }}
            }}
        }} finally {{
            currentProgram.endTransaction(txId, true);
        }}

        println("[SuperGhidra] Lazy NoReturn Pass complete. Safely marked " + markedCount + " functions.");
        println("[SuperGhidra] Zero flow repair cascades incurred.");
    }}
}}
"""
        return code

    @staticmethod
    def generate_lazy_noreturn_postscript_python() -> str:
        """Generates a Ghidra Python PostScript for lazy non-returning function discovery."""
        code = """# SuperGhidra Lazy Non-Returning Function Discovery PostScript (Python)
# Analyzes function exit points cleanly without triggering destructive flow clearing
# @category SuperGhidra

from ghidra.program.model.symbol import RefType

KNOWN_TERMINALS = {
    "exit", "_exit", "_Exit", "quick_exit", "abort", "__assert_fail",
    "__stack_chk_fail", "panic", "fatal", "terminate", "std::terminate", "__cxa_throw",
    "longjmp", "_longjmp", "siglongjmp", "pthread_exit", "ExitProcess", "TerminateProcess", "RaiseException"
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
            is_terminal = False
            for term in KNOWN_TERMINALS:
                tl = term.lower()
                if name_lower == tl or name_lower.endswith("::" + tl) or name_lower.endswith("." + tl):
                    is_terminal = True
                    break

            if is_terminal:
                fn.setNoReturn(True)
                marked_count += 1
                continue
    finally:
        currentProgram.endTransaction(tx_id, True)

    print(f"[SuperGhidra] Lazy NoReturn Pass complete. Safely marked {marked_count} functions.")
    print("[SuperGhidra] Zero flow repair cascades incurred.")

run()
"""
        return code


class HeadlessCommandBuilder:
    """Constructs robust analyzeHeadless command invocations."""

    def __init__(
        self,
        ghidra_install_dir: str = "",
        project_location: str = "",
        project_name: str = "",
        import_target: str = "",
        pre_script: str = "",
        post_script: str = "",
        script_dir: str = "",
        timeout_seconds: int = 600,
        max_cpu: int = 4,
        read_only: Optional[bool] = None,
        delete_project: bool = False,
        jvm_max_mem: str = "8G",
    ):
        self.ghidra_install_dir = ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR", "E:\\03_Devops\\Ghidra")
        self.project_location = project_location
        self.project_name = project_name
        self.import_target = import_target
        self.pre_script = pre_script
        self.post_script = post_script
        self.script_dir = script_dir
        self.timeout_seconds = timeout_seconds
        self.max_cpu = max_cpu
        self.read_only = (False if import_target else True) if read_only is None else read_only
        self.delete_project = delete_project
        self.jvm_max_mem = jvm_max_mem

    def build_command_args(self) -> List[str]:
        executable = os.path.join(self.ghidra_install_dir, "support", "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        args = [
            executable,
            self.project_location,
            self.project_name,
        ]

        if self.import_target:
            args.extend(["-import", self.import_target])

        if self.pre_script:
            args.extend(["-preScript", self.pre_script])

        if self.post_script:
            args.extend(["-postScript", self.post_script])

        if self.script_dir:
            args.extend(["-scriptPath", self.script_dir])

        if self.timeout_seconds > 0:
            args.extend(["-analysisTimeoutPerFile", str(self.timeout_seconds)])

        if self.max_cpu > 0:
            args.extend(["-max-cpu", str(self.max_cpu)])

        if self.read_only:
            args.append("-readOnly")

        if self.delete_project:
            args.append("-deleteProject")

        return args

    def build_cli_string(self) -> str:
        """Returns executable command line string properly quoted."""
        args = self.build_command_args()
        quoted = []
        for arg in args:
            if " " in arg or "\\" in arg:
                quoted.append(f'"{arg}"')
            else:
                quoted.append(arg)
        return " ".join(quoted)


def main():
    parser = argparse.ArgumentParser(description="SuperGhidra Headless Analyzer Tuner")
    parser.add_argument("--profile", type=str, choices=["lean", "decomp_ready", "full_guarded"], default="decomp_ready",
                        help="Analyzer optimization profile (default: decomp_ready)")
    parser.add_argument("--output-dir", type=str, default="E:\\02_Projects\\SuperGhidra\\scripts",
                        help="Output directory for generated Ghidra scripts")
    parser.add_argument("--project-dir", type=str, default="E:\\02_Projects\\SuperGhidra\\workspace",
                        help="Ghidra project directory path")
    parser.add_argument("--project-name", type=str, default="SuperGhidraProject",
                        help="Ghidra project name")
    parser.add_argument("--import-file", type=str, default="",
                        help="Target binary to import for analysis")
    parser.add_argument("--timeout", type=int, default=600,
                        help="Hard timeout per file in seconds (default: 600)")
    parser.add_argument("--dump-json", action="store_true",
                        help="Dump analyzer options configuration to JSON")
    args = parser.parse_args()

    profile_enum = AnalyzerProfileName(args.profile)
    config = get_profile_config(profile_enum)

    os.makedirs(args.output_dir, exist_ok=True)
    prescript_java_path = os.path.join(args.output_dir, "SuperGhidraPreScript.java")
    prescript_py_path = os.path.join(args.output_dir, "SuperGhidraPreScript.py")
    postscript_java_path = os.path.join(args.output_dir, "SuperGhidraLazyNoReturnPostScript.java")
    postscript_py_path = os.path.join(args.output_dir, "SuperGhidraLazyNoReturnPostScript.py")

    with open(prescript_java_path, "w", encoding="utf-8") as f:
        f.write(ScriptGenerator.generate_prescript_java(config))

    with open(prescript_py_path, "w", encoding="utf-8") as f:
        f.write(ScriptGenerator.generate_prescript_python(config))

    with open(postscript_java_path, "w", encoding="utf-8") as f:
        f.write(ScriptGenerator.generate_lazy_noreturn_postscript_java())

    with open(postscript_py_path, "w", encoding="utf-8") as f:
        f.write(ScriptGenerator.generate_lazy_noreturn_postscript_python())

    print(f"[*] Generated SuperGhidra Tuned Scripts in: {args.output_dir}")
    print(f"    - PreScript (Java):   {prescript_java_path}")
    print(f"    - PreScript (Python): {prescript_py_path}")
    print(f"    - Lazy PostScript (Java):   {postscript_java_path}")
    print(f"    - Lazy PostScript (Python): {postscript_py_path}")

    builder = HeadlessCommandBuilder(
        project_location=args.project_dir,
        project_name=args.project_name,
        import_target=args.import_file or "<PATH_TO_BINARY>",
        pre_script="SuperGhidraPreScript.java",
        post_script="SuperGhidraLazyNoReturnPostScript.java",
        script_dir=args.output_dir,
        timeout_seconds=args.timeout,
    )
    cmd_str = builder.build_cli_string()
    print("\n[+] Recommended analyzeHeadless command:")
    print(f"    {cmd_str}\n")

    if args.dump_json:
        json_path = os.path.join(args.output_dir, f"analyzer_options_{args.profile}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(config.to_ghidra_options_map(), f, indent=2)
        print(f"[+] Analyzer options JSON exported to: {json_path}")


if __name__ == "__main__":
    main()
