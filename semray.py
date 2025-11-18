# -*- coding: utf-8 -*-
"""
summary: High-performance, AI-driven semantic analysis for the IDA Pro decompiler.

description:
  This plugin, SemRay, integrates with Google's Generative AI API (Gemini) to
  provide suggestions for function names, comments, and local variable renames.

  This final, merged version combines the best features of previous implementations:
  • ROBUSTNESS: Gracefully falls back to basic IDA API calls if the 'codedump'
    plugin is not available, ensuring functionality in all environments.
  • MODULARITY: A clean, refactored architecture for better readability and maintenance.
  • NO CODE DUPLICATION: Adheres to the DRY principle by importing shared logic
    from 'codedump' when available, rather than duplicating it.
  • ENHANCED CONTEXT: When 'codedump' is present, it leverages its advanced context
    discovery (virtual calls, jump tables, detailed xref reasons) and optional PTN
    provenance annotations for richer semantic input to the LLM.
  • FLEXIBILITY: Allows the user to select either Hex-Rays decompilation or raw
    disassembly as the content for analysis.
  • USABILITY: Can be invoked from context menus in both the Pseudocode and
    Disassembly views, with clear dialogs for user input.

  Requires:
  - IDA Pro 7.6+ (with Python 3 and PyQt5 support)
  - Hex-Rays Decompiler (for decompilation mode and PTN analysis)
  - google-genai library (`pip install google-genai`)
  - pydantic library (`pip install pydantic`)
  - A Google AI API Key set in the environment variable `GOOGLE_API_KEY`.
"""

# --- Imports ---
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_name
import ida_bytes
import idaapi
import idautils
import idc
import ida_xref
import ida_typeinf
import ida_nalt
import ida_ua
import ida_idp
import ida_search

import threading
import json
import textwrap
import os
import sys
import traceback
import time
import re
from collections import deque, defaultdict
from functools import partial
from typing import Dict, List, Set, Optional, Tuple

# Ensure sibling plugin directories are importable (allow importing 'codedump.*')
try:
    _THIS_DIR = os.path.dirname(__file__)
    _PARENT = os.path.abspath(os.path.join(_THIS_DIR, ".."))
    if _PARENT not in sys.path:
        sys.path.append(_PARENT)
except Exception:
    pass

# --- Optional CodeDumper integration imports ---
CODEDUMP_AVAILABLE = False
try:
    from codedump import (
        find_callers_recursive as cd_find_callers_recursive,
        find_callees_recursive as cd_find_callees_recursive,
        decompile_functions_main as cd_decompile_functions_main,
        disassemble_functions_main as cd_disassemble_functions_main,
        find_vtables as cd_find_vtables,
    )
    from micro_analyzer import analyze_functions_ctree as cd_analyze_functions_ctree
    from ptn_utils import PTNEmitter as CD_PTNEmitter

    CODEDUMP_AVAILABLE = True
    print("SemRay DEBUG: CodeDumper integration available.")
except Exception as _e:
    CODEDUMP_AVAILABLE = False
    print(f"SemRay WARNING: CodeDumper not available ({_e}). Falling back to internal context logic.")

# Third-party libraries
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QScrollArea,
                                 QLabel, QVBoxLayout, QHBoxLayout, QGridLayout,
                                 QGroupBox, QCheckBox, QPushButton, QFrame,
                                 QTabWidget)

    print("SemRay DEBUG: PyQt5 imported successfully.")
except ImportError:
    print("SemRay Error: PyQt5 not found. Please ensure it's installed in IDA's Python environment.")

try:
    from pydantic import BaseModel, Field

    print("SemRay DEBUG: pydantic imported successfully.")
except ImportError:
    print("SemRay Error: pydantic not found. Please install it: pip install pydantic")

try:
    from google import genai
    from google.genai import types
    from google.genai import errors as google_genai_errors

    print("SemRay DEBUG: google-genai imported successfully.")
except ImportError:
    print("SemRay Error: google-genai not found. Please install it: pip install google-genai")

# --- Configuration ---
PLUGIN_NAME = "SemRay (Google AI Semantic Analysis)"
ACTION_ID_CTX_PREFIX_MULTI = "semray:googleai:ctx:multi:"
ACTION_ID_CTX_PREFIX_SINGLE = "semray:googleai:ctx:single:"
ACTION_ID_CTX_PREFIX_DEPTH = "semray:googleai:ctx:depth:"
MENU_PATH_CTX = "SemRay Analysis/"

# Google AI Configuration
GOOGLE_AI_API_KEY = os.environ.get("GOOGLE_API_KEY")
DEFAULT_GEMINI_MODEL = "gemini-flash-latest"
MODELS_TO_REGISTER = [DEFAULT_GEMINI_MODEL]

# Safety settings
try:
    DEFAULT_SAFETY_SETTINGS = [
        types.SafetySetting(category='HARM_CATEGORY_HATE_SPEECH', threshold='BLOCK_NONE'),
        types.SafetySetting(category='HARM_CATEGORY_DANGEROUS_CONTENT', threshold='BLOCK_NONE'),
        types.SafetySetting(category='HARM_CATEGORY_HARASSMENT', threshold='BLOCK_NONE'),
        types.SafetySetting(category='HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold='BLOCK_NONE'),
        types.SafetySetting(category='HARM_CATEGORY_CIVIC_INTEGRITY', threshold='BLOCK_NONE'),
    ]
    print("SemRay DEBUG: Default safety settings configured.")
except Exception:
    DEFAULT_SAFETY_SETTINGS = []

# Default depths
DEFAULT_CONTEXT_CALLER_DEPTH = 1
DEFAULT_CONTEXT_CALLEE_DEPTH = 1
DEFAULT_ANALYSIS_DEPTH = 1

# Content mode for LLM
CONTENT_MODE_DECOMP = "decomp"
CONTENT_MODE_ASM = "asm"
DEFAULT_CONTENT_MODE = CONTENT_MODE_DECOMP

# Allowed xref types (used with CodeDumper)
DEFAULT_XREF_TYPES = {'direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call',
                      'jump_table'}

# --- Concurrency Control ---
g_analysis_in_progress = set()
g_multi_analysis_active = False
g_analysis_lock = threading.Lock()
print("SemRay DEBUG: Concurrency control initialized.")

# -----------------------------------------------------------------------------
# 1.  DATA MODELS
# -----------------------------------------------------------------------------
_BAD_NAME_RE = re.compile(r"\\b(var\\d+|v\\d+|tmp|foo|bar|helper|unused)\\b", re.I)


def _lint_name(name: str) -> bool:
    return _BAD_NAME_RE.search(name) is None


class VariableRename(BaseModel):
    original_name: str = Field(..., description="The original variable/argument name as seen in pseudocode.")
    new_name: str = Field(..., description="The suggested descriptive name.")
    rename_reason: str = Field(..., description="Why this rename clarifies semantics.")
    rename_reason_findings: str = Field(..., description="Evidence or observations that justify the rename.")


class SingleFunctionAnalysis(BaseModel):
    original_function_name: str = Field(..., description="Exactly as in the '// === Function:' header.")
    function_name: str = Field(..., description="IDA‑style concise descriptive name.")
    comment: str = Field(..., description="Multi‑line C‑style block comment (without /* */).")
    variables: List[VariableRename] = Field(..., description="Suggested variable/argument renames for this function.")
    observations: List[dict] = Field(..., description="Notable observations influencing interpretation.")
    function_name_reason: str = Field(..., description="Rationale for the chosen function name.")
    function_name_reason_findings: str = Field(..., description="Evidence backing the chosen function name.")
    comment_reason: str = Field(..., description="Rationale for the comment block.")
    comment_reason_findings: str = Field(..., description="Evidence backing the comment block.")


class MultiFunctionAnalysisResult(BaseModel):
    function_analyses: List[SingleFunctionAnalysis]


# -----------------------------------------------------------------------------
# 2.  JSON SCHEMA
# -----------------------------------------------------------------------------
explicit_multi_function_analysis_schema: Dict = {
    "type": "object",
    "properties": {
        "function_analyses": {
            "type": "array",
            "description": "Per‑function analysis results.",
            "items": {
                "type": "object",
                "properties": {
                    "original_function_name": {"type": "string"},
                    "observations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "observation": {"type": "string"},
                                "observation_impact": {"type": "string"},
                            },
                            "required": ["observation", "observation_impact"],
                        },
                    },
                    "function_name_reason": {"type": "string"},
                    "function_name_reason_findings": {"type": "string"},
                    "function_name": {"type": "string"},
                    "comment_reason": {"type": "string"},
                    "comment_reason_findings": {"type": "string"},
                    "comment": {"type": "string"},
                    "variables": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "rename_reason": {"type": "string"},
                                "rename_reason_findings": {"type": "string"},
                                "original_name": {"type": "string"},
                                "new_name": {"type": "string"},
                            },
                            "required": ["rename_reason", "rename_reason_findings", "original_name", "new_name"],
                        },
                    },
                },
                "required": [
                    "original_function_name", "observations", "function_name_reason",
                    "function_name_reason_findings", "function_name", "comment_reason",
                    "comment_reason_findings", "comment", "variables"
                ],
            },
        }
    },
    "required": ["function_analyses"],
}


# -----------------------------------------------------------------------------
# 3.  Helper utilities
# -----------------------------------------------------------------------------
def get_function_prototype(ea: int) -> Optional[str]:
    try:
        return idc.get_type(ea) or ida_typeinf.idc_get_type(ea)
    except Exception:
        return None


def _gather_literals_main(ea: int, out: list) -> int:
    func = ida_funcs.get_func(ea)
    if not func:
        out.append([])
        return 1
    literals: list[str] = []
    it = func.start_ea
    while it < func.end_ea:
        flags = ida_bytes.get_full_flags(it)
        if ida_bytes.is_strlit(flags):
            s = ida_bytes.get_strlit_contents(it, -1, ida_nalt.get_str_type(it))
            if s:
                head = s[:40].decode("utf-8", "ignore") if isinstance(s, bytes) else str(s)[:40]
                literals.append(f'string:"{head}"')
        it = ida_bytes.next_head(it, func.end_ea)
    insn = ida_ua.insn_t()
    it = func.start_ea
    while it < func.end_ea:
        ilen = ida_ua.decode_insn(insn, it)
        if ilen == 0:
            it = idc.next_head(it, func.end_ea)
            continue
        for op in insn.ops:
            if op.type == idaapi.o_imm and op.value > 0xFFFF:
                literals.append(f"const:0x{op.value:X}")
        it += ilen
    out.append(literals)
    return 1


def gather_literals(ea: int) -> List[str]:
    holder: list = []
    ida_kernwin.execute_sync(lambda: _gather_literals_main(ea, holder), ida_kernwin.MFF_READ)
    return holder[0] if holder else []


# -----------------------------------------------------------------------------
# 4.  Context Builder (CodeDumper-aware with fallbacks)
# -----------------------------------------------------------------------------
def _format_asm_block(func_ea: int, func_name: str, items: List[Tuple[str, int, str]]) -> str:
    lines_out = [f"// --- ASM Function: {func_name} (0x{func_ea:X}) ---"]
    for kind, ea, text in items:
        lines_out.append(text if kind == "label" else f"0x{ea:X}: {text}")
    lines_out.append(f"// --- End ASM Function: {func_name} (0x{func_ea:X}) ---")
    return "\n".join(lines_out)


def _edges_to_strings(edges: Dict[int, Dict[int, Set[str]]], name_map: Dict[int, str]) -> List[str]:
    lines = []
    for src in sorted(edges.keys()):
        dsts = edges.get(src)
        if not dsts: continue
        parts = [f"{name_map.get(dst, f'sub_{dst:X}')} [{'/'.join(sorted(reasons))}]"
                 for dst, reasons in sorted(dsts.items())]
        if parts:
            lines.append(f"{name_map.get(src, f'sub_{src:X}')} -> {', '.join(parts)}")
    return lines


def _fallback_decompile_functions_main(eas_to_decompile: Set[int]) -> Dict[int, str]:
    results: Dict[int, str] = {}
    if not ida_hexrays.init_hexrays_plugin():
        return {ea: f"// Decompilation FAILED - Hex-Rays unavailable" for ea in eas_to_decompile}
    for func_ea in sorted(list(eas_to_decompile)):
        func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            results[func_ea] = str(cfunc) if cfunc else f"// Decompilation FAILED for {func_name}"
        except ida_hexrays.DecompilationFailure as e:
            results[func_ea] = f"// Decompilation ERROR for {func_name}: {e}"
    return results


def build_context_material(start_eas: Set[int],
                           caller_depth: int,
                           callee_depth: int,
                           content_mode: str) -> Tuple[Dict[int, str],
Dict[int, str],
Dict[int, Dict[int, Set[str]]],
Dict[int, str]]:
    """Must run in the IDA main thread."""
    print(f"SemRay DEBUG: Building context (callers={caller_depth}, callees={callee_depth}, mode={content_mode})")
    all_nodes: Set[int] = set(start_eas)
    edges: Dict[int, Dict[int, Set[str]]] = defaultdict(lambda: defaultdict(set))

    # --- Collect Callers ---
    if caller_depth > 0:
        visited_callers: Set[int] = set()
        if CODEDUMP_AVAILABLE:
            for ea in start_eas:
                all_nodes.update(cd_find_callers_recursive(ea, 1, caller_depth, visited_callers, edges=edges,
                                                           allowed_types=DEFAULT_XREF_TYPES))
        else:  # Fallback
            q = deque([(ea, 0) for ea in start_eas])
            visited = set(start_eas)
            while q:
                cur, d = q.popleft()
                if d >= caller_depth: continue
                ref = ida_xref.get_first_cref_to(cur)
                while ref != idaapi.BADADDR:
                    f = ida_funcs.get_func(ref)
                    if f and f.start_ea not in visited:
                        all_nodes.add(f.start_ea)
                        edges[f.start_ea][cur].add('direct_call')
                        visited.add(f.start_ea)
                        q.append((f.start_ea, d + 1))
                    ref = ida_xref.get_next_cref_to(cur, ref)

    # --- Collect Callees/Refs ---
    if callee_depth > 0:
        visited_callees: Set[int] = set()
        if CODEDUMP_AVAILABLE:
            vtables = cd_find_vtables()
            for ea in start_eas:
                all_nodes.update(
                    cd_find_callees_recursive(ea, 1, callee_depth, visited_callees, edges=edges, vtables=vtables,
                                              allowed_types=DEFAULT_XREF_TYPES))
        else:  # Fallback
            q = deque([(ea, 0) for ea in start_eas])
            visited = set(start_eas)
            while q:
                cur, d = q.popleft()
                if d >= callee_depth: continue
                f = ida_funcs.get_func(cur)
                if not f: continue
                for item_ea in idautils.FuncItems(cur):
                    for ref_ea in idautils.CodeRefsFrom(item_ea, 1):
                        ref_f = ida_funcs.get_func(ref_ea)
                        if ref_f and ref_f.start_ea not in visited:
                            all_nodes.add(ref_f.start_ea)
                            edges[cur][ref_f.start_ea].add('direct_call')
                            visited.add(ref_f.start_ea)
                            q.append((ref_f.start_ea, d + 1))

    # --- Name Map ---
    name_map = {ea: (ida_funcs.get_func_name(ea) or f"sub_{ea:X}") for ea in all_nodes}

    # --- Materialize Code Blocks ---
    codes_by_ea: Dict[int, str] = {}
    if content_mode == CONTENT_MODE_ASM:
        if CODEDUMP_AVAILABLE:
            asm_dict = cd_disassemble_functions_main(all_nodes)
        else:  # Fallback
            asm_dict = {}
            for fea in all_nodes:
                items = [("label", fea, f"{name_map[fea]}:")]
                items.extend(("inst", i_ea, idc.GetDisasm(i_ea) or "") for i_ea in idautils.FuncItems(fea))
                asm_dict[fea] = items
        for fea, items in asm_dict.items():
            codes_by_ea[fea] = _format_asm_block(fea, name_map[fea], items)
    else:  # Decompilation
        if CODEDUMP_AVAILABLE:
            codes_by_ea = cd_decompile_functions_main(all_nodes)
        else:  # Fallback
            codes_by_ea = _fallback_decompile_functions_main(all_nodes)

    # --- PTN Annotations (only if CodeDumper is available) ---
    ptn_ann: Dict[int, str] = {}
    if CODEDUMP_AVAILABLE and ida_hexrays.init_hexrays_plugin():
        try:
            fsums = cd_analyze_functions_ctree(all_nodes)
            emitter = CD_PTNEmitter(fsums)
            ptn_ann = emitter.per_function_annotations(max(1, callee_depth))
        except Exception as e:
            print(f"SemRay WARNING: PTN analysis failed: {e}")

    print(f"SemRay DEBUG: Context built. Nodes={len(all_nodes)}, Codes={len(codes_by_ea)}")
    return codes_by_ea, name_map, edges, ptn_ann


# -----------------------------------------------------------------------------
# 5.  Main async_call
# -----------------------------------------------------------------------------
def async_call(
        start_eas: Set[int],
        context_caller_depth: int,
        context_callee_depth: int,
        model_name: str,
        analysis_mode: str,
        analysis_depth: int = 0,
        extra_context: Optional[str] = None,
        content_mode: str = DEFAULT_CONTENT_MODE,
):
    if not start_eas: return
    primary_ea = min(start_eas)

    # Phase 1: Build context (MAIN THREAD)
    mat_holder: list = [None]

    def _collect_ctx_material(holder):
        ida_kernwin.show_wait_box(
            f"Collecting context (Callers={context_caller_depth}, Callees={context_callee_depth})...")
        try:
            holder.append(build_context_material(start_eas, context_caller_depth, context_callee_depth, content_mode))
            return 1
        finally:
            ida_kernwin.hide_wait_box()

    if ida_kernwin.execute_sync(lambda: _collect_ctx_material(mat_holder), ida_kernwin.MFF_READ) != 1 or not mat_holder[
        1]:
        print("SemRay Error: failed to build context.")
        return
    all_codes, ea_to_name, edges, ptn_ann = mat_holder[1]

    # Phase 2: Determine analysis targets
    target_analysis_eas: Set[int]
    if analysis_mode == 'current':
        target_analysis_eas = start_eas.intersection(all_codes.keys())
    elif analysis_mode == 'all':
        target_analysis_eas = set(all_codes.keys())
    elif analysis_mode == 'depth_limited':
        target_container: list = [None]
        ida_kernwin.execute_sync(
            lambda: target_container.append(find_functions_within_depth(start_eas, analysis_depth)),
            ida_kernwin.MFF_READ)
        target_analysis_eas = (target_container[1] or start_eas).intersection(all_codes.keys())
    else:
        target_analysis_eas = start_eas.intersection(all_codes.keys())
    if not target_analysis_eas:
        print("SemRay Error: No target functions after filtering.")
        return

    # Phase 3: Build prompt
    code_blocks = []
    for ea in sorted(all_codes):
        header = f"// === Function: {ea_to_name.get(ea, f'sub_{ea:X}')} (0x{ea:X}) ==="
        proto = get_function_prototype(ea)
        proto_hdr = f"// prototype: {proto}" if proto and content_mode == CONTENT_MODE_DECOMP else ""
        body = all_codes[ea]
        code_blocks.append("\n".join(filter(None, [header, proto_hdr, body])))

    call_edges_lines = _edges_to_strings(edges, ea_to_name)
    semantic_tags = [f"{ea_to_name[ea]} tags: {', '.join(gather_literals(ea))}" for ea in start_eas if
                     ea in ea_to_name and gather_literals(ea)]
    ptn_lines = [ptn_ann[ea] for ea in sorted(ptn_ann.keys()) if ea in target_analysis_eas]

    persona_block = f"You are an expert reverse engineer. The input is {content_mode} from IDA Pro."
    target_func_names = sorted([ea_to_name[ea] for ea in target_analysis_eas if ea in ea_to_name])
    scope_instr = (f"Analyze ONLY the following function(s): {', '.join(target_func_names)}. "
                   "Use other functions for background context only.") if analysis_mode != 'all' else "Analyze EVERY function provided."

    prompt_content = "\
\
".join(filter(None, [
        persona_block,
        "### NAMING CONTRACT\n- Encode role and domain (e.g., crc32_checksum).\n- Placeholders like `tmp`, `v5` are forbidden.",
        "Respond with pure JSON adhering to the supplied schema. Field `original_function_name` must match the header exactly.",
        scope_instr,
        "### CALLGRAPH\
" + ("\n".join(call_edges_lines) if call_edges_lines else "(none)"),
        "### PTN SEMANTICS (for analyzed targets)\
" + ("\n".join(ptn_lines) if ptn_lines else "(none)"),
        "### SEMANTICS (Primary Functions)\
" + ("\n".join(semantic_tags) if semantic_tags else "(none)"),
        "### START CODE CONTEXT\
" + "\
\
/* --- */\
\
".join(code_blocks) + "\
### END CODE CONTEXT",
        "### SELF‑REVIEW (mandatory, ≤ 120 words)\nAfter the JSON, list any generic identifiers left and explain why."
    ]))

    # Phase 4: Query LLM
    ida_kernwin.execute_ui_requests([lambda: ida_kernwin.show_wait_box("HIDECANCEL\nQuerying LLM...")])
    result_holder, exc_holder = [None], [None]

    def _llm_worker():
        try:
            result_holder[0] = do_google_ai_analysis(prompt_content, model_name)
        except Exception as e:
            exc_holder[0] = e

    t = threading.Thread(target=_llm_worker)
    t.start()
    try:
        while t.is_alive():
            if ida_kernwin.user_cancelled(): break
            time.sleep(0.1)
        t.join()
    finally:
        ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

    if ida_kernwin.user_cancelled() or exc_holder[0] or not result_holder[0]:
        if exc_holder[0]: print(f"SemRay Error: LLM call failed: {exc_holder[0]}")
        return

    # Phase 5: Map and lint results
    name_to_ea = {v: k for k, v in ea_to_name.items()}
    mapped = []
    for ana in result_holder[0]:
        oname = ana.get("original_function_name")
        if not oname or oname not in name_to_ea: continue
        ea = name_to_ea[oname]
        if ea not in target_analysis_eas: continue
        if not ana.get("function_name") or not _lint_name(ana["function_name"]): continue
        if any(not v.get("new_name") or not _lint_name(v["new_name"]) for v in ana.get("variables", [])): continue
        ana["function_ea"] = ea
        mapped.append(ana)

    # Phase 6: Update UI
    if mapped:
        ida_kernwin.execute_ui_requests([partial(do_show_ui, mapped, primary_ea)])
    else:
        ida_kernwin.warning("SemRay: No valid analysis results after filtering.")


# --- UI Widgets (unchanged logic) ---
class FunctionNameWidget(QWidget):
    accepted = True

    def __init__(self, function_name):
        super(FunctionNameWidget, self).__init__()
        layout = QHBoxLayout()
        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(lambda s: setattr(self, 'accepted', s == QtCore.Qt.Checked))
        self.name_label = QLabel(function_name)
        layout.addWidget(self.checkbox)
        layout.addWidget(self.name_label)
        group_box = QGroupBox("Suggested Function Name")
        group_box.setLayout(layout)
        main_layout = QVBoxLayout()
        main_layout.addWidget(group_box)
        self.setLayout(main_layout)


class CommentWidget(QWidget):
    accepted = True

    def __init__(self, comment):
        super(CommentWidget, self).__init__()
        layout = QHBoxLayout()
        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(lambda s: setattr(self, 'accepted', s == QtCore.Qt.Checked))
        self.comment_area = QLabel(comment)
        self.comment_area.setWordWrap(True)
        self.comment_area.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        layout.addWidget(self.checkbox)
        layout.addWidget(self.comment_area)
        group_box = QGroupBox("Suggested Comment")
        group_box.setLayout(layout)
        main_layout = QVBoxLayout()
        main_layout.addWidget(group_box)
        self.setLayout(main_layout)


class VariableWidget(QWidget):
    def __init__(self, variables):
        super(VariableWidget, self).__init__()
        group_layout = QGridLayout()
        group_layout.setColumnStretch(1, 1)
        group_layout.setColumnStretch(3, 1)
        self.checkboxes = []
        self.variable_data = variables
        for i, var_data in enumerate(variables):
            row, col_base = i // 2, (i % 2) * 4
            checkbox = QCheckBox()
            checkbox.setCheckState(QtCore.Qt.Checked)
            self.checkboxes.append(checkbox)
            group_layout.addWidget(checkbox, row, col_base + 0)
            group_layout.addWidget(QLabel(var_data.get('original_name', 'N/A')), row, col_base + 1)
            group_layout.addWidget(QLabel("→"), row, col_base + 2, QtCore.Qt.AlignCenter)
            group_layout.addWidget(QLabel(var_data.get('new_name', 'N/A')), row, col_base + 3)
        group_box = QGroupBox("Suggested Variable Renames")
        group_box.setLayout(group_layout)
        main_layout = QVBoxLayout()
        main_layout.addWidget(group_box)
        self.setLayout(main_layout)

    def get_selected_variables(self):
        return [self.variable_data[i] for i, cb in enumerate(self.checkboxes) if cb.isChecked()]


class SemRayUIForm(ida_kernwin.PluginForm):
    def __init__(self, analysis_results_list, primary_trigger_ea):
        super(SemRayUIForm, self).__init__()
        self.analysis_results = analysis_results_list or []
        self.primary_trigger_ea = primary_trigger_ea
        self.widgets_by_ea = {}
        self.parent_widget = None

    def OnCreate(self, form):
        self.parent_widget = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        main_layout = QVBoxLayout()
        tab_widget = QTabWidget()
        sorted_results = sorted(self.analysis_results, key=lambda r: r.get('function_ea', 0))
        for result_data in sorted_results:
            func_ea = result_data.get('function_ea')
            if func_ea is None: continue
            func_name_ida = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:X}"
            tab_title = f"{func_name_ida} (0x{func_ea:X})"
            tab_content_widget = QWidget()
            tab_layout = QVBoxLayout(tab_content_widget)
            name_widget = FunctionNameWidget(result_data.get('function_name', 'N/A'))
            comment_widget = CommentWidget(result_data.get('comment', 'No comment.'))
            variable_widget = VariableWidget(result_data.get('variables', [])) if result_data.get('variables') else None
            tab_layout.addWidget(name_widget)
            tab_layout.addWidget(comment_widget)
            if variable_widget: tab_layout.addWidget(variable_widget)
            tab_layout.addStretch(1)
            scroll_area = QScrollArea()
            scroll_area.setWidgetResizable(True)
            scroll_area.setWidget(tab_content_widget)
            tab_widget.addTab(scroll_area, tab_title)
            self.widgets_by_ea[func_ea] = {'name': name_widget, 'comment': comment_widget, 'vars': variable_widget,
                                           'data': result_data}
        main_layout.addWidget(tab_widget)
        accept_button = QPushButton("Apply Selected")
        accept_button.clicked.connect(self.on_accept_clicked)
        cancel_button = QPushButton("Close")
        cancel_button.clicked.connect(self.Close)
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(accept_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)
        self.parent_widget.setLayout(main_layout)
        self.parent_widget.setMinimumSize(600, 500)

    def on_accept_clicked(self):
        changes_by_ea = {}
        for func_ea, widgets in self.widgets_by_ea.items():
            data = widgets['data']
            changes = {
                'function_name': data.get('function_name') if widgets['name'].accepted else None,
                'comment': data.get('comment') if widgets['comment'].accepted else None,
                'variables': widgets['vars'].get_selected_variables() if widgets['vars'] else []
            }
            if any(changes.values()):
                changes_by_ea[func_ea] = changes
        if changes_by_ea:
            ida_kernwin.execute_sync(lambda: self._perform_ida_updates(changes_by_ea), ida_kernwin.MFF_WRITE)
        self.Close(0)

    def _rename_lvar(self, func_ea: int, cfunc, lv, new_name: str) -> bool:
        if hasattr(cfunc, "set_lvar_name"):
            try:
                return cfunc.set_lvar_name(lv, new_name)
            except Exception:
                pass
        if hasattr(cfunc, "rename_lvar"):
            try:
                return cfunc.rename_lvar(lv, new_name)
            except Exception:
                pass
        try:
            return ida_hexrays.rename_lvar(func_ea, lv.name, new_name)
        except Exception:
            return False

    def _perform_ida_updates(self, changes_by_ea: Dict[int, dict]) -> bool:
        overall_success = True
        refresh_needed = False
        vdui_refreshed = set()

        for func_ea, changes in changes_by_ea.items():
            func_t = ida_funcs.get_func(func_ea)
            if changes.get('comment') and func_t:
                wrapped = "\n".join(textwrap.wrap(changes['comment'], width=80))
                if not ida_funcs.set_func_cmt(func_t, wrapped, False):
                    overall_success = False
                else:
                    refresh_needed = True
            if changes.get('function_name'):
                if not ida_name.set_name(func_ea, changes['function_name'], ida_name.SN_CHECK | ida_name.SN_FORCE):
                    overall_success = False
                else:
                    refresh_needed = True
            if changes.get('variables'):
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if cfunc:
                        lvars_map = {lv.name: lv for lv in cfunc.get_lvars()}
                        renamed_any = False
                        for item in changes['variables']:
                            if item['original_name'] in lvars_map:
                                if self._rename_lvar(func_ea, cfunc, lvars_map[item['original_name']],
                                                     item['new_name']):
                                    renamed_any = True
                        if renamed_any:
                            ida_hexrays.mark_cfunc_dirty(func_ea)
                            refresh_needed = True
                except ida_hexrays.DecompilationFailure:
                    overall_success = False

            if refresh_needed and func_ea not in vdui_refreshed:
                widget = ida_kernwin.find_widget(f"Pseudocode-A:{func_ea:X}")
                if widget:
                    vdui = ida_hexrays.get_widget_vdui(widget)
                    if vdui:
                        vdui.refresh_view(True)
                        vdui_refreshed.add(func_ea)

        if refresh_needed:
            ida_kernwin.refresh_idaview_anyway()

        return overall_success

    def OnClose(self, form):
        SemRayUI.open_forms.pop(self.primary_trigger_ea, None)


class SemRayUI:
    open_forms = {}

    def __init__(self, analysis_results_list, primary_trigger_ea):
        if primary_trigger_ea in self.open_forms:
            try:
                self.open_forms[primary_trigger_ea].GetWidget().activateWindow()
            except:  # Window may have been closed
                self.open_forms.pop(primary_trigger_ea, None)
                self.__init__(analysis_results_list, primary_trigger_ea)  # Recurse
            return
        form = SemRayUIForm(analysis_results_list, primary_trigger_ea)
        self.open_forms[primary_trigger_ea] = form
        func_name = ida_funcs.get_func_name(primary_trigger_ea) or f"sub_{primary_trigger_ea:X}"
        form.Show(f"SemRay Suggestions: {func_name} Context", ida_kernwin.WOPN_PERSIST | ida_kernwin.WOPN_RESTORE)


def do_show_ui(results_list, primary_trigger_ea):
    SemRayUI(results_list, primary_trigger_ea)


# --- Action Handlers & Plugin Class ---
def find_functions_within_depth(start_eas: Set[int], max_depth: int) -> Set[int]:
    if max_depth <= 0: return start_eas
    q, visited = deque([(ea, 0) for ea in start_eas]), set(start_eas)
    while q:
        ea, depth = q.popleft()
        if depth >= max_depth: continue
        # Callers
        for ref in idautils.CodeRefsTo(ea, 1):
            f = ida_funcs.get_func(ref)
            if f and f.start_ea not in visited:
                visited.add(f.start_ea)
                q.append((f.start_ea, depth + 1))
        # Callees
        f = ida_funcs.get_func(ea)
        if f:
            for item_ea in idautils.FuncItems(ea):
                for ref in idautils.CodeRefsFrom(item_ea, 1):
                    callee_f = ida_funcs.get_func(ref)
                    if callee_f and callee_f.start_ea not in visited:
                        visited.add(callee_f.start_ea)
                        q.append((callee_f.start_ea, depth + 1))
    return visited


def do_google_ai_analysis(code_prompt, model_name):
    if not GOOGLE_AI_API_KEY:
        ida_kernwin.warning("SemRay Error: Google AI API Key not configured.")
        return None
    try:
        client = genai.Client(api_key=GOOGLE_AI_API_KEY)
        generation_config = types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=explicit_multi_function_analysis_schema,
            temperature=0.0,
            thinking_config=types.ThinkingConfig(thinking_budget=24576),
            safety_settings=DEFAULT_SAFETY_SETTINGS
        )
        response = client.models.generate_content(
            model=f'models/{model_name}', contents=code_prompt, config=generation_config
        )
        if not hasattr(response, 'text') or not response.text:
            ida_kernwin.warning(f"SemRay: Google AI response was empty or blocked.")
            return None
        raw_text = response.text
        json_match = re.search(r'```json\s*(\{.*?\})\s*```', raw_text, re.DOTALL)
        json_text = json_match.group(1) if json_match else raw_text
        parsed = json.loads(json_text)
        return parsed.get("function_analyses", [])
    except Exception as e:
        ida_kernwin.warning(f"SemRay: AI interaction error: {e}")
        traceback.print_exc()
        return None


def single_analysis_task_wrapper(primary_func_ea, context_caller_depth, context_callee_depth, model, analysis_mode,
                                 analysis_depth, context, content_mode):
    try:
        async_call(
            start_eas={primary_func_ea}, context_caller_depth=context_caller_depth,
            context_callee_depth=context_callee_depth, model_name=model,
            analysis_mode=analysis_mode, analysis_depth=analysis_depth,
            extra_context=context, content_mode=content_mode
        )
    finally:
        with g_analysis_lock:
            g_analysis_in_progress.discard(primary_func_ea)


def multi_analysis_task_wrapper(start_eas, caller_depth, callee_depth, model, context, content_mode):
    global g_multi_analysis_active
    try:
        async_call(
            start_eas=start_eas, context_caller_depth=caller_depth,
            context_callee_depth=callee_depth, model_name=model,
            analysis_mode='all', analysis_depth=0,
            extra_context=context, content_mode=content_mode
        )
    finally:
        with g_analysis_lock:
            g_multi_analysis_active = False


class CtxActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, model_name, analysis_mode='all'):
        self.model, self.analysis_mode = model_name, analysis_mode
        super().__init__()

    def activate(self, ctx):
        global g_analysis_in_progress, g_multi_analysis_active

        ea = idaapi.BADADDR
        try:
            if ctx.widget_type == ida_kernwin.BWN_DISASM:
                ea = ctx.cur_ea
            elif ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                vu = ida_hexrays.get_widget_vdui(ctx.widget)
                if vu and vu.cfunc:
                    ea = vu.cfunc.entry_ea
        except Exception:
            ea = ida_kernwin.get_screen_ea()

        f = ida_funcs.get_func(ea)
        if not f:
            ida_kernwin.warning("SemRay: Could not determine current function.")
            return 1

        primary_func_ea = f.start_ea
        with g_analysis_lock:
            if primary_func_ea in g_analysis_in_progress or g_multi_analysis_active:
                ida_kernwin.warning("SemRay: An analysis is already in progress.")
                return 1
            g_analysis_in_progress.add(primary_func_ea)

        content_choice = ida_kernwin.ask_buttons("Decompiled", "Assembly", "Cancel", 1, "Select content for LLM:")
        if content_choice == -1:  # Cancel
            with g_analysis_lock: g_analysis_in_progress.discard(primary_func_ea)
            return 1
        content_mode = CONTENT_MODE_DECOMP if content_choice == 1 else CONTENT_MODE_ASM

        a_depth = ida_kernwin.ask_long(DEFAULT_ANALYSIS_DEPTH,
                                       "Analysis Depth") if self.analysis_mode == 'depth_limited' else 0
        c_depth = ida_kernwin.ask_long(DEFAULT_CONTEXT_CALLER_DEPTH, "Context Caller Depth")
        ca_depth = ida_kernwin.ask_long(DEFAULT_CONTEXT_CALLEE_DEPTH, "Context Callee/Ref Depth")
        if c_depth is None or ca_depth is None or a_depth is None:
            with g_analysis_lock: g_analysis_in_progress.discard(primary_func_ea)
            return 1

        threading.Thread(target=single_analysis_task_wrapper, args=(
            primary_func_ea, c_depth, ca_depth, self.model, self.analysis_mode, a_depth, None, content_mode
        )).start()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type in (ida_kernwin.BWN_PSEUDOCODE,
                                                                        ida_kernwin.BWN_DISASM) else ida_kernwin.AST_DISABLE_FOR_WIDGET


class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        if ida_kernwin.get_widget_type(widget) in (ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_DISASM):
            for model in MODELS_TO_REGISTER:
                ida_kernwin.attach_action_to_popup(widget, popup_handle, f"{ACTION_ID_CTX_PREFIX_MULTI}{model}",
                                                   f"{MENU_PATH_CTX}", ida_kernwin.SETMENU_INS)
                ida_kernwin.attach_action_to_popup(widget, popup_handle, f"{ACTION_ID_CTX_PREFIX_SINGLE}{model}",
                                                   f"{MENU_PATH_CTX}", ida_kernwin.SETMENU_INS)
                ida_kernwin.attach_action_to_popup(widget, popup_handle, f"{ACTION_ID_CTX_PREFIX_DEPTH}{model}",
                                                   f"{MENU_PATH_CTX}", ida_kernwin.SETMENU_INS)


class semray_t(idaapi.plugin_t):
    flags, comment, help, wanted_name = idaapi.PLUGIN_PROC | idaapi.PLUGIN_FIX, PLUGIN_NAME, "Google AI assistance", PLUGIN_NAME
    hooks, registered_actions = None, []

    def init(self):
        for model in MODELS_TO_REGISTER:
            for mode, label in [('all', 'Analyze ALL Funcs in Context'), ('current', 'Analyze CURRENT Func Only'),
                                ('depth_limited', 'Analyze Current + N Levels')]:
                prefix = {'all': ACTION_ID_CTX_PREFIX_MULTI, 'current': ACTION_ID_CTX_PREFIX_SINGLE,
                          'depth_limited': ACTION_ID_CTX_PREFIX_DEPTH}[mode]
                action_id = f"{prefix}{model}"
                desc = ida_kernwin.action_desc_t(action_id, f"{label} ({model})", CtxActionHandler(model, mode), None,
                                                 None, 199)
                if ida_kernwin.register_action(desc): self.registered_actions.append(action_id)
        self.hooks = Hooks()
        self.hooks.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global g_multi_analysis_active
        with g_analysis_lock:
            if g_multi_analysis_active: return
            g_multi_analysis_active = True

        func_list_str = ida_kernwin.ask_str("", 0, "Enter comma-separated function names or addresses")
        if not func_list_str:
            with g_analysis_lock: g_multi_analysis_active = False
            return

        start_eas = set()
        for item in func_list_str.split(','):
            item_strip = item.strip()
            if not item_strip: continue
            ea = ida_name.get_name_ea(idaapi.BADADDR, item_strip)
            if ea == idaapi.BADADDR:
                try:
                    ea = int(item_strip, 0)
                except ValueError:
                    continue
            if ida_funcs.get_func(ea): start_eas.add(ea)

        if not start_eas:
            ida_kernwin.warning("SemRay: No valid functions found from input.")
            with g_analysis_lock: g_multi_analysis_active = False
            return

        content_choice = ida_kernwin.ask_buttons("Decompiled", "Assembly", "Cancel", 1, "Select content for LLM:")
        if content_choice == -1:
            with g_analysis_lock: g_multi_analysis_active = False
            return
        content_mode = CONTENT_MODE_DECOMP if content_choice == 1 else CONTENT_MODE_ASM

        c_depth = ida_kernwin.ask_long(DEFAULT_CONTEXT_CALLER_DEPTH, "Context Caller Depth")
        ca_depth = ida_kernwin.ask_long(DEFAULT_CONTEXT_CALLEE_DEPTH, "Context Callee/Ref Depth")
        if c_depth is None or ca_depth is None:
            with g_analysis_lock: g_multi_analysis_active = False
            return

        threading.Thread(target=multi_analysis_task_wrapper,
                         args=(start_eas, c_depth, ca_depth, DEFAULT_GEMINI_MODEL, None, content_mode)).start()

    def term(self):
        if self.hooks: self.hooks.unhook()
        for action in self.registered_actions: ida_kernwin.unregister_action(action)
        for form in list(SemRayUI.open_forms.values()): form.Close(0)


def PLUGIN_ENTRY():
    return semray_t()
