# -*- coding: utf-8 -*-
"""
CodeDumper + PTN

Summary:
  IDA Pro + Hex-Rays plugin to:
  1) Dump decompiled code for function(s) with callers/callees/refs; annotates each function block
     with compact provenance lines (@PTN) near the code, including upstream (I:) and downstream (E:) edges,
     aliases (A:), and global relationships (G:).
  2) Generate DOT graphs of the call graph.
  3) Generate PTN files describing dataflow provenance (locals/params/globals) across calls, including
     aliasing (e.g., &a1[123]) and global write→read relationships.
  4) Dump assembly for function(s) with callers/callees/refs in the same order & layout as the decompiled
     dump, including the same PTN annotations & xref summaries.
  5) Inject per-instruction @PTN hints inline in assembly by correlating callsites and global touches
     back to item EAs. (Uses CTREE to collect callsite EAs and expression EAs for global touches.)

Requirements:
  - IDA Pro 7.6+
  - Hex-Rays Decompiler
  - PyQt5 for dialogs (if missing, plugin still loads but dialogs may fail)
"""

import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_name
import ida_bytes
import idaapi
import idautils
import idc
import ida_xref
import ida_nalt
import ida_ua
import ida_idp
import ida_segment
import ida_ida
import ida_gdl
import ida_lines

import threading
import os
import sys
from functools import partial
import traceback
import time
import re
from collections import defaultdict
from typing import Dict, Set, List, Tuple

try:
    from PyQt5 import QtCore, QtGui, QtWidgets
except ImportError:
    pass

PLUGIN_DIR = os.path.dirname(__file__)
if PLUGIN_DIR and PLUGIN_DIR not in sys.path:
    sys.path.append(PLUGIN_DIR)

from ptn_utils import PTNEmitter, FunctionSummary  # type: ignore
from micro_analyzer import analyze_functions_ctree  # type: ignore

PLUGIN_NAME = "CodeDumper"
ACTION_ID_CTX = "codedumper:dump_callers_callees_refs_ctx"
ACTION_LABEL_CTX = "Dump Function + Callers/Callees/Refs..."
ACTION_TOOLTIP_CTX = "Decompile current function, callers, callees, and referenced functions to a C file"
ACTION_ID_DOT_CTX = "codedumper:generate_dot_ctx"
ACTION_LABEL_DOT_CTX = "Generate DOT Graph + Callers/Callees/Refs..."
ACTION_TOOLTIP_DOT_CTX = "Generate DOT graph for current function, callers, callees, and referenced functions"
ACTION_ID_PTN_CTX = "codedumper:generate_ptn_ctx"
ACTION_LABEL_PTN_CTX = "Generate PTN + Callers/Callees/Refs..."
ACTION_TOOLTIP_PTN_CTX = "Generate PTN provenance for current function, callers, callees, and references"
ACTION_ID_PTN_COPY_CTX = "codedumper:copy_ptn_var_ctx"
ACTION_LABEL_PTN_COPY_CTX = "Copy PTN for Identifier Under Cursor"
ACTION_TOOLTIP_PTN_COPY_CTX = "Copy provenance lines for identifier under cursor"

# Assembly dump actions (single & multi)
ACTION_ID_ASM_CTX = "codedumper:dump_asm_ctx"
ACTION_LABEL_ASM_CTX = "Dump Assembly + Callers/Callees/Refs..."
ACTION_TOOLTIP_ASM_CTX = "Disassemble current function, callers, callees, and referenced functions to an ASM file"

MENU_PATH_CTX = "Dump code/"

ACTION_ID_CODE_MULTI = "codedumper:dump_code_multi"
ACTION_LABEL_CODE_MULTI = "Dump Code for Multiple Functions..."
ACTION_TOOLTIP_CODE_MULTI = "Decompile a list of functions and their combined callers/callees/refs to a C file"
ACTION_ID_DOT_MULTI = "codedumper:generate_dot_multi"
ACTION_LABEL_DOT_MULTI = "Generate DOT Graph for Multiple Functions..."
ACTION_TOOLTIP_DOT_MULTI = "Generate DOT graph for a list of functions and their combined callers/callees/refs"
ACTION_ID_PTN_MULTI = "codedumper:generate_ptn_multi"
ACTION_LABEL_PTN_MULTI = "Generate PTN for Multiple Functions..."
ACTION_TOOLTIP_PTN_MULTI = "Generate PTN for a list of functions and their combined callers/callees/refs"
ACTION_ID_ASM_MULTI = "codedumper:dump_asm_multi"
ACTION_LABEL_ASM_MULTI = "Dump Assembly for Multiple Functions..."
ACTION_TOOLTIP_ASM_MULTI = "Disassemble a list of functions and their combined callers/callees/refs to an ASM file"

MENU_PATH_MULTI = f"Edit/{PLUGIN_NAME}/"

g_dump_in_progress = set()
g_multi_dump_active = False
g_dump_lock = threading.Lock()

def find_callers_recursive(target_ea, current_depth, max_depth, visited_eas, edges=None, allowed_types=None):
    if allowed_types is None:
        allowed_types = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
    if current_depth > max_depth:
        return set()
    if target_ea in visited_eas:
        return set()
    visited_eas.add(target_ea)
    callers = set()
    ref_ea = ida_xref.get_first_cref_to(target_ea)
    while ref_ea != idaapi.BADADDR:
        caller_func = ida_funcs.get_func(ref_ea)
        if caller_func:
            caller_ea = caller_func.start_ea
            if 'direct_call' in allowed_types:
                if edges is not None:
                    edges[caller_ea][target_ea].add('direct_call')
                if caller_ea not in visited_eas:
                    callers.add(caller_ea)
                    callers.update(find_callers_recursive(caller_ea, current_depth + 1, max_depth, visited_eas, edges=edges, allowed_types=allowed_types))
        ref_ea = ida_xref.get_next_cref_to(target_ea, ref_ea)
    return callers

def detect_indirect_target(ea, func_start_ea, bb_start, bb_end):
    possible_targets = set()
    mnem = idc.print_insn_mnem(ea)
    if mnem not in ['call', 'jmp']:
        return possible_targets
    op_type = idc.get_operand_type(ea, 0)
    if op_type in [idaapi.o_reg, idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ]:
        current_ea = ea - idc.get_item_size(ea)
        traced_regs = set()
        if op_type == idaapi.o_reg:
            traced_regs.add(idc.get_operand_value(ea, 0))
        elif op_type in [idaapi.o_phrase, idaapi.o_displ]:
            traced_regs.add(idc.get_operand_value(ea, 0))
        while current_ea >= bb_start and current_ea < bb_end:
            prev_mnem = idc.print_insn_mnem(current_ea)
            if prev_mnem.startswith('mov'):
                prev_op_type0 = idc.get_operand_type(current_ea, 0)
                prev_op_type1 = idc.get_operand_type(current_ea, 1)
                if prev_op_type0 == idaapi.o_reg and idc.get_operand_value(current_ea, 0) in traced_regs:
                    if prev_op_type1 == idaapi.o_imm:
                        imm_val = idc.get_operand_value(current_ea, 1)
                        if ida_funcs.get_func(imm_val):
                            possible_targets.add(imm_val)
                    elif prev_op_type1 == idaapi.o_mem:
                        mem_addr = idc.get_operand_value(current_ea, 1)
                        if ida_bytes.is_func(ida_bytes.get_flags(mem_addr)):
                            possible_targets.add(mem_addr)
                    traced_regs.remove(idc.get_operand_value(current_ea, 0))
                    if not traced_regs:
                        break
            current_ea -= idc.get_item_size(current_ea)
    return possible_targets

def detect_jump_tables(ea):
    si = ida_nalt.get_switch_info(ea)
    if si:
        cases = ida_xref.calc_switch_cases(ea, si)
        if cases:
            targets = set(cases.targets)
            return [tgt for tgt in targets if ida_funcs.get_func(tgt)]
    op_type = idc.get_operand_type(ea, 0)
    if op_type == idaapi.o_displ and idc.print_insn_mnem(ea) == 'jmp':
        base = idc.get_operand_value(ea, 0)
        entries = []
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        for i in range(20):
            ptr = ida_bytes.get_qword(base + i * ptr_size) if ptr_size == 8 else ida_bytes.get_dword(base + i * ptr_size)
            if ptr == 0 or not ida_funcs.get_func(ptr):
                break
            entries.append(ptr)
        if len(entries) > 1:
            return entries
    return []

def find_vtables():
    vtables = {}
    code_seg = ida_segment.get_segm_by_name(".text") or ida_segment.get_segm_by_name("__text")
    if not code_seg:
        return vtables
    data_segs = [ida_segment.getseg(s) for s in idautils.Segments()
                 if (ida_segment.getseg(s).perm & ida_segment.SEGPERM_EXEC) == 0 and
                    (ida_segment.getseg(s).perm & ida_segment.SEGPERM_WRITE) == 0]
    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    for seg in data_segs:
        ea = seg.start_ea
        end = seg.end_ea
        while ea < end:
            if ea % ptr_size != 0:
                ea += 1
                continue
            count = 0
            vfuncs = []
            current = ea
            while current < end:
                ptr = ida_bytes.get_qword(current) if ptr_size == 8 else ida_bytes.get_dword(current)
                if ptr == 0 or not ida_funcs.get_func(ptr) or ida_segment.getseg(ptr).start_ea != code_seg.start_ea:
                    break
                vfuncs.append(ptr)
                count += 1
                current += ptr_size
            if count >= 3:
                vtables[ea] = vfuncs
                ea = current
            else:
                ea += ptr_size
    return vtables

def resolve_virtual_calls(target_ea, edges, vtables, allowed_types):
    if 'virtual_call' not in allowed_types:
        return
    func = ida_funcs.get_func(target_ea)
    if not func:
        return
    current_item_ea = func.start_ea
    while current_item_ea < func.end_ea:
        mnem = idc.print_insn_mnem(current_item_ea)
        if mnem == 'call':
            op_type = idc.get_operand_type(current_item_ea, 0)
            if op_type == idaapi.o_displ:
                offset = idc.get_operand_value(current_item_ea, 1)
                ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                index = offset // ptr_size if ptr_size else 0
                for vt_ea, vfuncs in vtables.items():
                    if index < len(vfuncs):
                        vfunc = vfuncs[index]
                        edges[target_ea][vfunc].add('virtual_call')
        current_item_ea = idc.next_head(current_item_ea, func.end_ea)

def detect_dynamic_imports(target_ea, edges):
    resolver_ea = ida_name.get_name_ea(idaapi.BADADDR, "GetProcAddress")
    if resolver_ea == idaapi.BADADDR:
        return
    for xref in idautils.XrefsTo(resolver_ea, 0):
        if xref.type == ida_xref.fl_CN:
            call_ea = xref.frm
            next_ea = idc.next_head(call_ea)
            while next_ea < ida_funcs.get_func(call_ea).end_ea:
                mnem = idc.print_insn_mnem(next_ea)
                if mnem == 'call' and idc.get_operand_type(next_ea, 0) == idaapi.o_reg:
                    pass
                next_ea = idc.next_head(next_ea)

def find_callees_recursive(target_ea, current_depth, max_depth, visited_eas, edges=None, vtables=None, allowed_types=None):
    if allowed_types is None:
        allowed_types = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
    if current_depth > max_depth:
        return set()
    if target_ea in visited_eas:
        return set()
    visited_eas.add(target_ea)
    callees_and_refs = set()
    func = ida_funcs.get_func(target_ea)
    if not func:
        return callees_and_refs
    if vtables is None:
        vtables = find_vtables()
    if edges:
        resolve_virtual_calls(target_ea, edges, vtables, allowed_types)
        detect_dynamic_imports(target_ea, edges)

    current_item_ea = func.start_ea
    insn = ida_ua.insn_t()
    next_insn = ida_ua.insn_t()
    flowchart = ida_gdl.FlowChart(func)

    while current_item_ea < func.end_ea and current_item_ea != idaapi.BADADDR:
        insn_len = ida_ua.decode_insn(insn, current_item_ea)
        if insn_len == 0:
            next_ea = idc.next_head(current_item_ea, func.end_ea)
            if next_ea <= current_item_ea: break
            current_item_ea = next_ea
            continue

        bb = next((b for b in flowchart if b.start_ea <= current_item_ea < b.end_ea), None)
        if bb and 'indirect_call' in allowed_types:
            indirect_targets = detect_indirect_target(current_item_ea, func.start_ea, bb.start_ea, bb.end_ea)
            for itgt in indirect_targets:
                if edges is not None:
                    edges[target_ea][itgt].add('indirect_call')
                if itgt not in visited_eas:
                    callees_and_refs.add(itgt)
                    recursive_results = find_callees_recursive(itgt, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                    callees_and_refs.update(recursive_results)

        if 'jump_table' in allowed_types:
            jt_targets = detect_jump_tables(current_item_ea)
            for jtt in jt_targets:
                if edges is not None:
                    edges[target_ea][jtt].add('jump_table')
                if jtt not in visited_eas:
                    callees_and_refs.add(jtt)
                    recursive_results = find_callees_recursive(jtt, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                    callees_and_refs.update(recursive_results)

        cref_ea = ida_xref.get_first_cref_from(current_item_ea)
        while cref_ea != idaapi.BADADDR:
            ref_func = ida_funcs.get_func(cref_ea)
            if ref_func and ref_func.start_ea == cref_ea:
                if 'direct_call' in allowed_types:
                    if edges is not None:
                        edges[target_ea][cref_ea].add('direct_call')
                    if cref_ea not in visited_eas:
                        callees_and_refs.add(cref_ea)
                        recursive_results = find_callees_recursive(cref_ea, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                        callees_and_refs.update(recursive_results)
            cref_ea = ida_xref.get_next_cref_from(current_item_ea, cref_ea)

        dref_ea = ida_xref.get_first_dref_from(current_item_ea)
        while dref_ea != idaapi.BADADDR:
            ref_func = ida_funcs.get_func(dref_ea)
            if ref_func and ref_func.start_ea == dref_ea:
                if 'data_ref' in allowed_types:
                    if edges is not None:
                        edges[target_ea][dref_ea].add('data_ref')
                    if dref_ea not in visited_eas:
                        callees_and_refs.add(dref_ea)
                        recursive_results = find_callees_recursive(dref_ea, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                        callees_and_refs.update(recursive_results)
            dref_ea = ida_xref.get_next_dref_from(current_item_ea, dref_ea)

        is_push_imm_func = False
        pushed_func_addr = idaapi.BADADDR

        for i in range(idaapi.UA_MAXOP):
            op = insn.ops[i]
            if op.type == idaapi.o_void: break
            if op.type == idaapi.o_imm:
                imm_val = op.value
                ref_func = ida_funcs.get_func(imm_val)
                if ref_func and ref_func.start_ea == imm_val:
                    mnem = insn.get_canon_mnem()
                    added = False
                    if 'immediate_ref' in allowed_types:
                        if edges is not None:
                            edges[target_ea][imm_val].add('immediate_ref')
                        added = True
                    if mnem == "push":
                        is_push_imm_func = True
                        pushed_func_addr = imm_val
                    if is_push_imm_func:
                        next_insn_ea = current_item_ea + insn_len
                        if next_insn_ea < func.end_ea:
                            next_insn_len = ida_ua.decode_insn(next_insn, next_insn_ea)
                            if next_insn_len > 0:
                                if ida_idp.is_ret_insn(next_insn, ida_idp.IRI_RET_LITERALLY):
                                    if 'tail_call_push_ret' in allowed_types:
                                        if edges is not None:
                                            edges[target_ea][pushed_func_addr].add('tail_call_push_ret')
                                        added = True
                    if added:
                        if imm_val not in visited_eas:
                            callees_and_refs.add(imm_val)
                            recursive_results = find_callees_recursive(imm_val, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                            callees_and_refs.update(recursive_results)

        next_ea = current_item_ea + insn_len
        if next_ea <= current_item_ea:
            next_ea = idc.next_head(current_item_ea, func.end_ea)
            if next_ea <= current_item_ea: break
        current_item_ea = next_ea

    return callees_and_refs

def decompile_functions_main(eas_to_decompile):
    results = {}
    total = len(eas_to_decompile)
    count = 0
    if not ida_hexrays.init_hexrays_plugin():
        for func_ea in eas_to_decompile:
            func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
            results[func_ea] = f"// Decompilation FAILED for {func_name} (0x{func_ea:X}) - Hex-Rays init failed"
        return results
    sorted_eas_list = sorted(list(eas_to_decompile))
    for func_ea in sorted_eas_list:
        count += 1
        func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
        ida_kernwin.replace_wait_box(f"Decompiling {count}/{total}: {func_name}")
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                results[func_ea] = str(cfunc)
            else:
                results[func_ea] = f"// Decompilation FAILED for {func_name} (0x{func_ea:X}) - Decompiler returned None"
        except ida_hexrays.DecompilationFailure as e:
            results[func_ea] = f"// Decompilation ERROR for {func_name} (0x{func_ea:X}): {e}"
        except Exception as e:
            results[func_ea] = f"// Decompilation UNEXPECTED ERROR for {func_name} (0x{func_ea:X}): {e}"
            traceback.print_exc()
    return results

def disassemble_functions_main(eas_to_disasm) -> Dict[int, List[Tuple[str, int, str]]]:
    """
    Disassemble the functions identified by 'eas_to_disasm' and return a dict:
      ea -> list of tuples (kind, ea, text) where kind ∈ {'label','inst'}.
    For 'label' entries, 'ea' is the address of the label (0 for function header label).
    For 'inst' entries, 'ea' is the instruction EA, and 'text' is the disassembly for that item.
    Runs in the IDA main thread via execute_sync (caller responsibility).
    """
    results: Dict[int, List[Tuple[str, int, str]]] = {}
    total = len(eas_to_disasm)
    count = 0
    sorted_eas_list = sorted(list(eas_to_disasm))
    for func_ea in sorted_eas_list:
        count += 1
        func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
        ida_kernwin.replace_wait_box(f"Disassembling {count}/{total}: {func_name}")
        func = ida_funcs.get_func(func_ea)
        if not func:
            results[func_ea] = [("label", 0, f"; Disassembly FAILED for {func_name} (0x{func_ea:X}) - no function at address")]
            continue
        lines: List[Tuple[str, int, str]] = []
        # Emit a function header label for readability in the ASM body.
        lines.append(("label", 0, f"{func_name}:"))
        try:
            for ea in idautils.FuncItems(func_ea):
                # Insert a local label if this address has a visible name (e.g., 'loc_...' labels).
                try:
                    lab = ida_name.get_name(ea) or ""
                except Exception:
                    lab = ""
                if lab and ea != func_ea:
                    lines.append(("label", ea, f"{lab}:"))
                # Preferred disassembly line generation (with tag removal).
                s = None
                try:
                    s = ida_lines.generate_disasm_line(ea, 0)
                    if s:
                        try:
                            s = ida_lines.tag_remove(s)
                        except Exception:
                            pass
                except Exception:
                    s = None
                if not s:
                    try:
                        s = idc.GetDisasm(ea)
                    except Exception:
                        s = None
                if not s:
                    try:
                        item_sz = idc.get_item_size(ea) or 1
                    except Exception:
                        item_sz = 1
                    bytes_repr = " ".join(f"{ida_bytes.get_wide_byte(ea+i):02X}" for i in range(item_sz))
                    s = f"db {bytes_repr}"
                lines.append(("inst", ea, s))
        except Exception:
            traceback.print_exc()
            lines.append(("label", 0, "; ERROR: Exception during disassembly traversal"))
        results[func_ea] = lines
    return results

def get_edge_style(reasons_set):
    if 'virtual_call' in reasons_set:
        return "bold"
    if 'direct_call' in reasons_set:
        return "solid"
    if 'tail_call_push_ret' in reasons_set:
        return "dashed,bold"
    if 'indirect_call' in reasons_set or 'jump_table' in reasons_set:
        return "dashed"
    if 'data_ref' in reasons_set or 'immediate_ref' in reasons_set:
        return "dotted"
    return "dotted"

def _augment_edges_with_ctree_calls(fs_summaries: Dict[int, FunctionSummary], edges):
    for fea, fs in fs_summaries.items():
        for au in fs.arguses:
            if au.callee_ea:
                edges[fea][au.callee_ea].add('direct_call')

def write_code_file(output_file_path, decompiled_results, start_func_eas, caller_depth, callee_depth, edges, fs_summaries: Dict[int, FunctionSummary], max_chars=0):
    num_funcs_written = 0
    try:
        name_map_container = [{}]
        eas_to_get_names = list(decompiled_results.keys())

        def get_names_main(eas, container):
            names = {}
            for ea in eas:
                names[ea] = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            container[0] = names
            return 1

        sync_status = ida_kernwin.execute_sync(lambda: get_names_main(eas_to_get_names, name_map_container), ida_kernwin.MFF_READ)
        name_map = name_map_container[0] if sync_status == 1 else {ea: f"sub_{ea:X}" for ea in eas_to_get_names}

        all_nodes = set(decompiled_results.keys())

        # Augment edges with ctree-derived direct calls (catches PLT/IAT like strcpy)
        _augment_edges_with_ctree_calls(fs_summaries, edges)

        out_degrees = [(len(edges[ea]), ea) for ea in all_nodes]
        sorted_out_degrees = sorted(out_degrees, key=lambda x: (x[0], x[1]))
        sorted_eas = [t[1] for t in sorted_out_degrees]

        ptn = PTNEmitter(fs_summaries)
        per_func_ann = ptn.per_function_annotations(max(1, callee_depth))

        included_eas = set(all_nodes)
        removed_eas = set()
        if max_chars > 0:
            func_blocks_for_sizing = []
            for func_ea in sorted_eas:
                func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
                incoming = [fr for fr in edges if func_ea in edges[fr]]
                outgoing = edges[func_ea]
                ann = per_func_ann.get(func_ea, "")
                code_or_error = decompiled_results[func_ea]
                block_str = ''.join([
                    f"// Incoming xrefs for {func_name} (0x{func_ea:X}): {len(incoming)} refs\n",
                    f"// Outgoing xrefs for {func_name} (0x{func_ea:X}): {len(outgoing)} refs\n",
                    ann,
                    f"// --- Function: {func_name}...\n", code_or_error, "\n// --- End Function...\n\n"
                ])
                func_blocks_for_sizing.append({'ea': func_ea, 'block_size': len(block_str), 'code_len': len(code_or_error)})

            current_size = sum(d['block_size'] for d in func_blocks_for_sizing)
            if current_size > max_chars:
                removable = [d for d in func_blocks_for_sizing if d['ea'] not in start_func_eas]
                removable.sort(key=lambda d: d['code_len'])
                while current_size > max_chars and removable:
                    to_remove = removable.pop(0)
                    included_eas.remove(to_remove['ea'])
                    removed_eas.add(to_remove['ea'])
                    current_size -= to_remove['block_size']

        sorted_included_eas = [ea for ea in sorted_eas if ea in included_eas]

        header_lines = []
        header_lines.append(f"// Decompiled code dump generated by {PLUGIN_NAME}\n")

        header_lines.append("\n")

        header_lines.append(
            "// --------\n"
            "#PTN v0\n"
            "// @PTN LEGEND\n"
            "// Nodes: L(F,i)=local i in function F; P(F,i)=param i of F; G(addr)=global at addr; F(Fx)=function Fx.\n"
            "// Slices: @[off:len] in bytes; '?' unknown; '&' = address-of; '*' = deref; optional cast as :(type).\n"
            "// A: alias inside function   => A: dst := src[@slice][mode][:cast] {meta}\n"
            "// I: inbound (caller→this)   => I: origin -> P(F,i) {caller=F?,cs=0x...,conf=...}\n"
            "// E: outbound (this→callee)  => E: origin -> A(F?,arg) [-> A(F?,arg)...] {cs=0x...,conf=...}\n"
            "// G: global touch/summary    => G: F(F?) -> G(0xADDR)   or   G: F(writer) -> G(0xADDR) -> F(reader)\n"
            "// Dictionary entry (per function block): // @PTN D:F?=0xEA,Name\n"
            "// --------\n"
        )

        header_lines.append("\n")

        if len(start_func_eas) == 1:
            start_ea = list(start_func_eas)[0]
            header_lines.append(f"// Start Function: 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")
        else:
            header_lines.append("// Start Functions:\n")
            for start_ea in sorted(list(start_func_eas)):
                header_lines.append(f"//   - 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")

        header_lines.append(f"// Caller Depth: {caller_depth}\n")
        header_lines.append(f"// Callee/Ref Depth: {callee_depth}\n")
        if max_chars > 0:
            header_lines.append(f"// Max Characters: {max_chars}\n")
        header_lines.append(f"// Total Functions Found: {len(all_nodes)}\n")
        header_lines.append(f"// Included Functions ({len(included_eas)}):\n")
        for func_ea in sorted_included_eas:
            func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
            header_lines.append(f"//   - {func_name} (0x{func_ea:X})\n")
        if removed_eas:
            header_lines.append(f"// Removed Functions ({len(removed_eas)}):\n")
            for func_ea in sorted(removed_eas):
                func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
                header_lines.append(f"//   - {func_name} (0x{func_ea:X})\n")
        else:
            header_lines.append(f"// Removed Functions: None\n")
        header_lines.append(f"// {'-'*60}\n\n")
        header = ''.join(header_lines)

        final_content_blocks = []
        for func_ea in sorted_included_eas:
            func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
            all_incoming = [fr for fr in edges if func_ea in edges[fr]]
            filtered_incoming = [fr for fr in all_incoming if fr in included_eas]
            incoming_strs = []
            for fr in sorted(filtered_incoming):
                reasons = sorted(edges[fr][func_ea])
                reason_str = '/'.join(reasons)
                src_name = name_map.get(fr, f"sub_{fr:X}")
                incoming_strs.append(f"{src_name} (0x{fr:X}) [{reason_str}]")
            incoming_line = f"// Incoming xrefs for {func_name} (0x{func_ea:X}): {', '.join(incoming_strs) or 'None'}\n"

            all_outgoing = edges[func_ea]
            filtered_outgoing = {to: reasons for to, reasons in all_outgoing.items() if to in included_eas}
            outgoing_strs = []
            for to in sorted(filtered_outgoing):
                reasons = sorted(filtered_outgoing[to])
                reason_str = '/'.join(reasons)
                dst_name = name_map.get(to, f"sub_{to:X}")
                outgoing_strs.append(f"{dst_name} (0x{to:X}) [{reason_str}]")
            outgoing_line = f"// Outgoing xrefs for {func_name} (0x{func_ea:X}): {', '.join(outgoing_strs) or 'None'}\n"

            code_or_error = decompiled_results[func_ea]
            ann = per_func_ann.get(func_ea, "")

            block = [
                incoming_line,
                outgoing_line,
                ann,
                f"// --- Function: {func_name} (0x{func_ea:X}) ---\n",
                code_or_error + "\n",
                f"// --- End Function: {func_name} (0x{func_ea:X}) ---\n\n"
            ]
            final_content_blocks.append(''.join(block))

        content = header + ''.join(final_content_blocks)
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(content)
        num_funcs_written = len(included_eas)
        return num_funcs_written

    except Exception as e:
        traceback.print_exc()
        error_msg = f"{PLUGIN_NAME}: Error writing dump file:\n{e}"
        ida_kernwin.execute_ui_requests([lambda msg=error_msg: ida_kernwin.warning(msg)])
        return 0

def write_asm_file(output_file_path, asm_results: Dict[int, List[Tuple[str, int, str]]],
                   start_func_eas, caller_depth, callee_depth, edges,
                   fs_summaries: Dict[int, FunctionSummary], max_chars=0):
    """
    Write an ASM dump mirroring the structure & ordering of write_code_file.
    Inject per-instruction @PTN hints inline (as trailing // comments or separate comment lines).
    """
    num_funcs_written = 0
    try:
        name_map_container = [{}]
        eas_to_get_names = list(asm_results.keys())

        def get_names_main(eas, container):
            names = {}
            for ea in eas:
                names[ea] = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            container[0] = names
            return 1

        sync_status = ida_kernwin.execute_sync(lambda: get_names_main(eas_to_get_names, name_map_container), ida_kernwin.MFF_READ)
        name_map = name_map_container[0] if sync_status == 1 else {ea: f"sub_{ea:X}" for ea in eas_to_get_names}

        all_nodes = set(asm_results.keys())

        _augment_edges_with_ctree_calls(fs_summaries, edges)

        out_degrees = [(len(edges[ea]), ea) for ea in all_nodes]
        sorted_out_degrees = sorted(out_degrees, key=lambda x: (x[0], x[1]))
        sorted_eas = [t[1] for t in sorted_out_degrees]

        ptn = PTNEmitter(fs_summaries)
        per_func_ann = ptn.per_function_annotations(max(1, callee_depth))
        # Per-instruction hints: fea -> {ea -> [hint_str_without_comment_prefix]}
        per_inst_hints = ptn.per_instruction_hints(max(1, callee_depth))

        def format_asm_with_hints(func_ea: int, items: List[Tuple[str, int, str]]) -> str:
            lines_out: List[str] = []
            hint_map = per_inst_hints.get(func_ea, {})
            for kind, ea, text in items:
                if kind == "label":
                    lines_out.append(text)
                    continue
                # 'inst' line
                line = f"0x{ea:X}: {text}"
                hints = hint_map.get(ea, [])
                if hints:
                    # Emit instruction, then per-hint short comment lines for readability
                    lines_out.append(line)
                    for h in hints:
                        lines_out.append(f"    // {h}")
                else:
                    lines_out.append(line)
            return "\n".join(lines_out)

        # Prepare blocks (including sizing with max_chars)
        included_eas = set(all_nodes)
        removed_eas = set()
        func_text_cache: Dict[int, str] = {}
        if max_chars > 0:
            func_blocks_for_sizing = []
            for func_ea in sorted_eas:
                func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
                incoming = [fr for fr in edges if func_ea in edges[fr]]
                outgoing = edges[func_ea]
                ann = per_func_ann.get(func_ea, "")
                code_text = func_text_cache.setdefault(func_ea, format_asm_with_hints(func_ea, asm_results[func_ea]))
                block_str = ''.join([
                    f"// Incoming xrefs for {func_name} (0x{func_ea:X}): {len(incoming)} refs\n",
                    f"// Outgoing xrefs for {func_name} (0x{func_ea:X}): {len(outgoing)} refs\n",
                    ann,
                    f"// --- Function: {func_name}...\n", code_text, "\n// --- End Function...\n\n"
                ])
                func_blocks_for_sizing.append({'ea': func_ea, 'block_size': len(block_str), 'code_len': len(code_text)})

            current_size = sum(d['block_size'] for d in func_blocks_for_sizing)
            if current_size > max_chars:
                removable = [d for d in func_blocks_for_sizing if d['ea'] not in start_func_eas]
                removable.sort(key=lambda d: d['code_len'])
                while current_size > max_chars and removable:
                    to_remove = removable.pop(0)
                    included_eas.remove(to_remove['ea'])
                    removed_eas.add(to_remove['ea'])
                    current_size -= to_remove['block_size']

        sorted_included_eas = [ea for ea in sorted_eas if ea in included_eas]

        header_lines = []
        header_lines.append(f"// Assembly dump generated by {PLUGIN_NAME}\n")

        header_lines.append("\n")

        header_lines.append(
            "// --------\n"
            "#PTN v0\n"
            "// @PTN LEGEND\n"
            "// Nodes: L(F,i)=local i in function F; P(F,i)=param i of F; G(addr)=global at addr; F(Fx)=function Fx.\n"
            "// Slices: @[off:len] in bytes; '?' unknown; '&' = address-of; '*' = deref; optional cast as :(type).\n"
            "// A: alias inside function   => A: dst := src[@slice][mode][:cast] {meta}\n"
            "// I: inbound (caller→this)   => I: origin -> P(F,i) {caller=F?,cs=0x...,conf=...}\n"
            "// E: outbound (this→callee)  => E: origin -> A(F?,arg) [-> A(F?,arg)...] {cs=0x...,conf=...}\n"
            "// G: global touch/summary    => G: F(F?) -> G(0xADDR)   or   G: F(writer) -> G(0xADDR) -> F(reader)\n"
            "// Dictionary entry (per function block): // @PTN D:F?=0xEA,Name\n"
            "// --------\n"
        )

        header_lines.append("\n")

        if len(start_func_eas) == 1:
            start_ea = list(start_func_eas)[0]
            header_lines.append(f"// Start Function: 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")
        else:
            header_lines.append("// Start Functions:\n")
            for start_ea in sorted(list(start_func_eas)):
                header_lines.append(f"//   - 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")

        header_lines.append(f"// Caller Depth: {caller_depth}\n")
        header_lines.append(f"// Callee/Ref Depth: {callee_depth}\n")
        if max_chars > 0:
            header_lines.append(f"// Max Characters: {max_chars}\n")
        header_lines.append(f"// Total Functions Found: {len(all_nodes)}\n")
        header_lines.append(f"// Included Functions ({len(included_eas)}):\n")
        for func_ea in sorted_included_eas:
            func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
            header_lines.append(f"//   - {func_name} (0x{func_ea:X})\n")
        if removed_eas:
            header_lines.append(f"// Removed Functions ({len(removed_eas)}):\n")
            for func_ea in sorted(removed_eas):
                func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
                header_lines.append(f"//   - {func_name} (0x{func_ea:X})\n")
        else:
            header_lines.append(f"// Removed Functions: None\n")
        header_lines.append(f"// {'-'*60}\n\n")
        header = ''.join(header_lines)

        final_content_blocks = []
        for func_ea in sorted_included_eas:
            func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
            all_incoming = [fr for fr in edges if func_ea in edges[fr]]
            filtered_incoming = [fr for fr in all_incoming if fr in included_eas]
            incoming_strs = []
            for fr in sorted(filtered_incoming):
                reasons = sorted(edges[fr][func_ea])
                reason_str = '/'.join(reasons)
                src_name = name_map.get(fr, f"sub_{fr:X}")
                incoming_strs.append(f"{src_name} (0x{fr:X}) [{reason_str}]")
            incoming_line = f"// Incoming xrefs for {func_name} (0x{func_ea:X}): {', '.join(incoming_strs) or 'None'}\n"

            all_outgoing = edges[func_ea]
            filtered_outgoing = {to: reasons for to, reasons in all_outgoing.items() if to in included_eas}
            outgoing_strs = []
            for to in sorted(filtered_outgoing):
                reasons = sorted(filtered_outgoing[to])
                reason_str = '/'.join(reasons)
                dst_name = name_map.get(to, f"sub_{to:X}")
                outgoing_strs.append(f"{dst_name} (0x{to:X}) [{reason_str}]")
            outgoing_line = f"// Outgoing xrefs for {func_name} (0x{func_ea:X}): {', '.join(outgoing_strs) or 'None'}\n"

            code_text = func_text_cache.get(func_ea) or format_asm_with_hints(func_ea, asm_results[func_ea])
            ann = per_func_ann.get(func_ea, "")

            block = [
                incoming_line,
                outgoing_line,
                ann,
                f"// --- Function: {func_name} (0x{func_ea:X}) ---\n",
                code_text + "\n",
                f"// --- End Function: {func_name} (0x{func_ea:X}) ---\n\n"
            ]
            final_content_blocks.append(''.join(block))

        content = header + ''.join(final_content_blocks)
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(content)
        num_funcs_written = len(included_eas)
        return num_funcs_written

    except Exception as e:
        traceback.print_exc()
        error_msg = f"{PLUGIN_NAME}: Error writing ASM file:\n{e}"
        ida_kernwin.execute_ui_requests([lambda msg=error_msg: ida_kernwin.warning(msg)])
        return 0

def write_dot_file(output_file_path, edges, all_nodes, start_func_eas, caller_depth, callee_depth):
    num_nodes_written = 0
    try:
        name_map = {}
        name_map_container = [{}]
        eas_to_get_names = list(all_nodes)

        def get_names_main(eas, container):
            names = {}
            for ea in eas:
                names[ea] = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            container[0] = names
            return 1

        sync_status = ida_kernwin.execute_sync(lambda: get_names_main(eas_to_get_names, name_map_container), ida_kernwin.MFF_READ)
        if sync_status == 1:
            name_map = name_map_container[0]
        else:
            for ea in eas_to_get_names:
                name_map[ea] = f"sub_{ea:X}"

        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(f"# DOT graph generated by {PLUGIN_NAME}\n")
            if len(start_func_eas) == 1:
                start_ea = list(start_func_eas)[0]
                f.write(f"# Start Function: 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")
            else:
                f.write("# Start Functions:\n")
                for start_ea in sorted(list(start_func_eas)):
                    f.write(f"#   - 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")
            f.write(f"# Caller Depth: {caller_depth}\n")
            f.write(f"# Callee/Ref Depth: {callee_depth}\n")
            f.write(f"# Total Nodes: {len(all_nodes)}\n")
            f.write("#\n# --- Legend ---\n")
            f.write("# Solid Line: Direct Call\n")
            f.write("# Bold Line: Virtual Call\n")
            f.write("# Dashed Line: Indirect Call / Jump Table\n")
            f.write("# Bold Dashed Line: Tail Call (push/ret)\n")
            f.write("# Dotted Line: Data / Immediate Reference\n")
            f.write(f"# {'-'*60}\n\n")

            f.write("digraph CallGraph {\n")
            f.write("    graph [splines=ortho];\n")
            f.write("    node [shape=box, style=filled, fillcolor=lightblue];\n")
            f.write("    edge [color=gray50];\n")

            sorted_nodes = sorted(list(all_nodes))
            for ea in sorted_nodes:
                name = name_map[ea]
                if len(name) > 40:
                    name = name[:37] + "..."
                label = f"{name}\\n(0x{ea:X})"
                fillcolor = "fillcolor=red" if ea in start_func_eas else ""
                f.write(f"    \"0x{ea:X}\" [label=\"{label}\" {fillcolor}];\n")

            for from_ea in sorted_nodes:
                if from_ea in edges:
                    for to_ea in sorted(edges[from_ea]):
                        if to_ea in all_nodes:
                            reasons_set = edges[from_ea][to_ea]
                            style = get_edge_style(reasons_set)
                            tooltip_str = '/'.join(sorted(reasons_set))
                            f.write(f"    \"0x{from_ea:X}\" -> \"0x{to_ea:X}\" [style={style}, tooltip=\"{tooltip_str}\"];\n")
            f.write("}\n")

        num_nodes_written = len(all_nodes)
        return num_nodes_written

    except Exception as e:
        traceback.print_exc()
        error_msg = f"{PLUGIN_NAME}: Error writing DOT file:\n{e}"
        ida_kernwin.execute_ui_requests([lambda msg=error_msg: ida_kernwin.warning(msg)])
        return 0

def write_ptn_file(output_file_path, fs_summaries: Dict[int, FunctionSummary], start_func_eas: Set[int], callee_depth: int):
    try:
        emitter = PTNEmitter(fs_summaries)
        if output_file_path.lower().endswith(".json"):
            content = emitter.emit_ptn_json(start_eas=start_func_eas, callee_depth=max(1, callee_depth), restrict_eas=None)
        else:
            content = emitter.emit_ptn(start_eas=start_func_eas, callee_depth=max(1, callee_depth), restrict_eas=None)
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return len(content)
    except Exception as e:
        traceback.print_exc()
        error_msg = f"{PLUGIN_NAME}: Error writing PTN file:\n{e}"
        ida_kernwin.execute_ui_requests([lambda msg=error_msg: ida_kernwin.warning(msg)])
        return 0

def dump_task(start_func_eas, caller_depth, callee_depth, output_file_path, mode='code', xref_types=None, max_chars=0):
    if xref_types is None:
        xref_types = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])

    global g_multi_dump_active, g_dump_in_progress

    start_func_names = []
    start_names_container = [[]]

    def get_start_names_main(eas, container):
        names = []
        for ea in eas:
            name = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            names.append(f"{name}(0x{ea:X})")
        container[0] = names
        return 1

    sync_status = ida_kernwin.execute_sync(lambda: get_start_names_main(start_func_eas, start_names_container), ida_kernwin.MFF_READ)
    if sync_status == 1:
        start_func_names = start_names_container[0]
    print(f"{PLUGIN_NAME}: Background task for {len(start_func_eas)} function(s) mode={mode}: {', '.join(start_func_names) if start_func_names else ''}")
    print(f"  Callers={caller_depth}, Callees={callee_depth}, Output={output_file_path}")
    print(f"  Xref Types: {', '.join(sorted(xref_types))}")
    print(f"  Max Chars: {max_chars}")

    try:
        all_nodes = set(start_func_eas)
        edges = defaultdict(lambda: defaultdict(set))
        ida_kernwin.execute_ui_requests([lambda: ida_kernwin.show_wait_box(f"Finding callers/callees/refs for {len(start_func_eas)} functions...")])

        visited_callers = set()
        if caller_depth > 0:
            caller_result_container = [set()]
            visited_caller_container = [set()]

            def run_find_multi_callers_main(container, visited_set_container, edges, allowed_types):
                combined_callers = set()
                for start_ea in start_func_eas:
                    found = find_callers_recursive(start_ea, 1, caller_depth, visited_set_container[0], edges=edges, allowed_types=allowed_types)
                    combined_callers.update(found)
                container[0] = combined_callers
                return 1

            sync_status = ida_kernwin.execute_sync(lambda: run_find_multi_callers_main(caller_result_container, visited_caller_container, edges, xref_types), ida_kernwin.MFF_READ)
            if sync_status == 1:
                total_caller_eas = caller_result_container[0]
                visited_callers = visited_caller_container[0]
                all_nodes |= visited_callers
                all_nodes.update(total_caller_eas)
            else:
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed to find callers.")
                return

        visited_callees = set()
        if callee_depth > 0:
            callee_result_container = [set()]
            visited_callee_container = [set()]

            def run_find_multi_callees_main(container, visited_set_container, edges, allowed_types):
                combined_callees = set()
                vtables = find_vtables()
                for start_ea in start_func_eas:
                    found = find_callees_recursive(start_ea, 1, callee_depth, visited_set_container[0], edges=edges, vtables=vtables, allowed_types=allowed_types)
                    combined_callees.update(found)
                container[0] = combined_callees
                return 1

            sync_status = ida_kernwin.execute_sync(lambda: run_find_multi_callees_main(callee_result_container, visited_callee_container, edges, xref_types), ida_kernwin.MFF_READ)
            if sync_status == 1:
                total_callee_ref_eas = callee_result_container[0]
                visited_callees = visited_callee_container[0]
                all_nodes |= visited_callees
                all_nodes.update(total_callee_ref_eas)
            else:
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed to find callees/refs.")
                return

        total_nodes = len(all_nodes)
        if total_nodes == 0:
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            ida_kernwin.warning(f"{PLUGIN_NAME}: No functions/nodes found.")
            return

        fs_summaries_container = [{}]
        def run_analyze_main(container, eas):
            try:
                container[0] = analyze_functions_ctree(eas)
                return 1
            except Exception:
                traceback.print_exc()
                container[0] = {}
                return 0

        analyze_status = ida_kernwin.execute_sync(lambda: run_analyze_main(fs_summaries_container, all_nodes), ida_kernwin.MFF_READ)
        fs_summaries: Dict[int, FunctionSummary] = fs_summaries_container[0] if analyze_status == 1 else {}

        if mode == 'code':
            decompiled_results = {}
            decomp_result_container = [{}]
            def run_decompile_main(container, eas):
                try:
                    container[0] = decompile_functions_main(eas)
                    return 1
                except Exception:
                    traceback.print_exc()
                    container[0] = {}
                    return 0
            sync_status = ida_kernwin.execute_sync(lambda: run_decompile_main(decomp_result_container, all_nodes), ida_kernwin.MFF_WRITE)
            if sync_status == 1:
                decompiled_results = decomp_result_container[0]
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            num_written = write_code_file(output_file_path, decompiled_results, start_func_eas, caller_depth, callee_depth, edges, fs_summaries, max_chars=max_chars)

        elif mode == 'graph':
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            num_written = write_dot_file(output_file_path, edges, all_nodes, start_func_eas, caller_depth, callee_depth)

        elif mode == 'ptn':
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            num_written = write_ptn_file(output_file_path, fs_summaries, set(all_nodes), callee_depth=max(1, callee_depth))

        elif mode == 'asm':
            asm_result_container = [{}]
            def run_disasm_main(container, eas):
                try:
                    container[0] = disassemble_functions_main(eas)
                    return 1
                except Exception:
                    traceback.print_exc()
                    container[0] = {}
                    return 0
            sync_status = ida_kernwin.execute_sync(lambda: run_disasm_main(asm_result_container, all_nodes), ida_kernwin.MFF_READ)
            asm_results = asm_result_container[0] if sync_status == 1 else {}
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            num_written = write_asm_file(output_file_path, asm_results, start_func_eas, caller_depth, callee_depth, edges, fs_summaries, max_chars=max_chars)

        else:
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            ida_kernwin.warning(f"{PLUGIN_NAME}: Unknown mode '{mode}'.")
            return

        if num_written > 0:
            type_str = "functions" if mode in ('code', 'asm') else ("nodes" if mode == 'graph' else "bytes")
            final_message = f"{PLUGIN_NAME}: Successfully wrote {num_written} {type_str} to:\n{output_file_path}"
            ida_kernwin.execute_sync(lambda: (ida_kernwin.info(final_message), 1)[1], ida_kernwin.MFF_WRITE)

    except Exception as e:
        traceback.print_exc()
        ida_kernwin.execute_ui_requests([lambda: ida_kernwin.warning(f"{PLUGIN_NAME}: An unexpected error occurred.")])
        ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
    finally:
        with g_dump_lock:
            if len(start_func_eas) == 1:
                g_dump_in_progress.discard(list(start_func_eas)[0])
            else:
                global g_multi_dump_active
                g_multi_dump_active = False

class DumpCtxActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        global g_dump_in_progress, g_multi_dump_active
        widget = ctx.widget
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return 1
        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Decompilation not available for this function.")
            return 1
        start_func_ea = vu.cfunc.entry_ea
        start_func_name = ida_funcs.get_func_name(start_func_ea) or f"sub_{start_func_ea:X}"
        with g_dump_lock:
            if start_func_ea in g_dump_in_progress:
                ida_kernwin.warning(f"{PLUGIN_NAME}: Dump already running for {start_func_name}.")
                return 1
            if g_multi_dump_active:
                ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function dump is currently running.")
                return 1
            g_dump_in_progress.add(start_func_ea)
        input_results = {"caller_depth": -1, "callee_depth": -1, "output_file": None, "xref_types": None, "max_chars": 0}
        input_container = [input_results]
        def get_inputs_main(container):
            c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
            if c_depth is None: return 0
            container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0
            ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
            if ca_depth is None: return 0
            container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0
            xref_types_str = ida_kernwin.ask_str("all", 0, "Enter comma-separated xref types to include (or 'all'):\n"
                                                         "direct_call,indirect_call,data_ref,immediate_ref,tail_call_push_ret,virtual_call,jump_table")
            if xref_types_str is None: return 0
            if xref_types_str.strip().lower() == 'all':
                container[0]["xref_types"] = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
            else:
                container[0]["xref_types"] = set([t.strip() for t in xref_types_str.split(',') if t.strip()])
            m_chars = ida_kernwin.ask_long(0, "Enter maximum characters for the output file (0 for no limit)")
            if m_chars is None: return 0
            container[0]["max_chars"] = int(m_chars) if m_chars >= 0 else 0
            default_filename = re.sub(r'[<>:"/\\|?*]', '_', f"{start_func_name}_dump_callers{c_depth}_callees{ca_depth}.c")
            output_file = ida_kernwin.ask_file(True, default_filename, "Select Output C File")
            if not output_file: return 0
            container[0]["output_file"] = output_file
            return 1
        sync_status = ida_kernwin.execute_sync(lambda: get_inputs_main(input_container), ida_kernwin.MFF_WRITE)
        final_inputs = input_container[0]
        caller_depth = final_inputs["caller_depth"]
        callee_depth = final_inputs["callee_depth"]
        output_file_path = final_inputs["output_file"]
        xref_types = final_inputs["xref_types"]
        max_chars = final_inputs["max_chars"]
        if sync_status != 1 or caller_depth < 0 or callee_depth < 0 or not output_file_path or not xref_types:
            with g_dump_lock:
                g_dump_in_progress.discard(start_func_ea)
            return 1
        task_thread = threading.Thread(target=dump_task, args=(set([start_func_ea]), caller_depth, callee_depth, output_file_path, 'code', xref_types, max_chars))
        task_thread.start()
        return 1
    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu and vu.cfunc:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class DumpDotCtxActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        global g_dump_in_progress, g_multi_dump_active
        widget = ctx.widget
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return 1
        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Not available for this function.")
            return 1
        start_func_ea = vu.cfunc.entry_ea
        start_func_name = ida_funcs.get_func_name(start_func_ea) or f"sub_{start_func_ea:X}"
        with g_dump_lock:
            if start_func_ea in g_dump_in_progress:
                ida_kernwin.warning(f"{PLUGIN_NAME}: Operation already running for {start_func_name}.")
                return 1
            if g_multi_dump_active:
                ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function operation is currently running.")
                return 1
            g_dump_in_progress.add(start_func_ea)

        input_results = {"caller_depth": -1, "callee_depth": -1, "output_file": None, "xref_types": None, "max_chars": 0}
        input_container = [input_results]
        def get_inputs_main(container):
            c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
            if c_depth is None: return 0
            container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0
            ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
            if ca_depth is None: return 0
            container[0]["callee_depth"] = int(ca_depth) if c_depth >= 0 else 0
            xref_types_str = ida_kernwin.ask_str("all", 0, "Enter comma-separated xref types to include (or 'all'):\n"
                                                         "direct_call,indirect_call,data_ref,immediate_ref,tail_call_push_ret,virtual_call,jump_table")
            if xref_types_str is None: return 0
            if xref_types_str.strip().lower() == 'all':
                container[0]["xref_types"] = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
            else:
                container[0]["xref_types"] = set([t.strip() for t in xref_types_str.split(',') if t.strip()])
            m_chars = ida_kernwin.ask_long(0, "Enter maximum characters for the output file (0 for no limit)")
            if m_chars is None: return 0
            container[0]["max_chars"] = int(m_chars) if m_chars >= 0 else 0
            default_filename = re.sub(r'[<>:"/\\|?*]', '_', f"{start_func_name}_graph_callers{c_depth}_callees{ca_depth}.dot")
            output_file = ida_kernwin.ask_file(True, default_filename, "Select Output DOT File")
            if not output_file: return 0
            container[0]["output_file"] = output_file
            return 1
        sync_status = ida_kernwin.execute_sync(lambda: get_inputs_main(input_container), ida_kernwin.MFF_WRITE)
        final_inputs = input_container[0]
        caller_depth = final_inputs["caller_depth"]
        callee_depth = final_inputs["callee_depth"]
        output_file_path = final_inputs["output_file"]
        xref_types = final_inputs["xref_types"]
        max_chars = final_inputs["max_chars"]
        if sync_status != 1 or caller_depth < 0 or callee_depth < 0 or not output_file_path or not xref_types:
            with g_dump_lock:
                g_dump_in_progress.discard(start_func_ea)
            return 1
        task_thread = threading.Thread(target=dump_task, args=(set([start_func_ea]), caller_depth, callee_depth, output_file_path, 'graph', xref_types, max_chars))
        task_thread.start()
        return 1
    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu and vu.cfunc:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class DumpPTNCtxActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        global g_dump_in_progress, g_multi_dump_active
        widget = ctx.widget
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return 1
        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Not available for this function.")
            return 1
        start_func_ea = vu.cfunc.entry_ea
        start_func_name = ida_funcs.get_func_name(start_func_ea) or f"sub_{start_func_ea:X}"
        with g_dump_lock:
            if start_func_ea in g_dump_in_progress:
                ida_kernwin.warning(f"{PLUGIN_NAME}: Operation already running for {start_func_name}.")
                return 1
            if g_multi_dump_active:
                ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function operation is currently running.")
                return 1
            g_dump_in_progress.add(start_func_ea)

        input_results = {"caller_depth": -1, "callee_depth": -1, "output_file": None}
        input_container = [input_results]
        def get_inputs_main(container):
            ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth for PTN (e.g., 1, 2)")
            if ca_depth is None: return 0
            container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 1 else 1
            default_filename = re.sub(r'[<>:"/\\|?*]', '_', f"{start_func_name}_provenance.ptn")
            output_file = ida_kernwin.ask_file(True, default_filename, "Select Output PTN File (.ptn or .json)")
            if not output_file: return 0
            container[0]["output_file"] = output_file
            container[0]["caller_depth"] = 0
            return 1
        sync_status = ida_kernwin.execute_sync(lambda: get_inputs_main(input_container), ida_kernwin.MFF_WRITE)
        final_inputs = input_container[0]
        callee_depth = final_inputs["callee_depth"]
        output_file_path = final_inputs["output_file"]
        if sync_status != 1 or callee_depth < 1 or not output_file_path:
            with g_dump_lock:
                g_dump_in_progress.discard(start_func_ea)
            return 1
        task_thread = threading.Thread(target=dump_task, args=(set([start_func_ea]), 0, callee_depth, output_file_path, 'ptn', set(), 0))
        task_thread.start()
        return 1
    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu and vu.cfunc:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class CopyPTNVarCtxActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        widget = ctx.widget
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
            return 1
        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Not available for this function.")
            return 1
        func_ea = vu.cfunc.entry_ea
        def run_collect_current_fs():
            try:
                return analyze_functions_ctree([func_ea]).get(func_ea)
            except Exception:
                traceback.print_exc()
                return None
        fs = None
        ida_kernwin.execute_sync(lambda: None, ida_kernwin.MFF_READ)
        fs = run_collect_current_fs()
        if not fs:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Could not compute provenance for current function.")
            return 1
        ident = ""
        try:
            t = ida_kernwin.get_highlight(widget)
            if t and t[0]:
                ident = t[0]
        except Exception:
            ident = ""
        from ptn_utils import PTNEmitter  # local import
        emitter = PTNEmitter({func_ea: fs})
        ann = emitter.per_function_annotations(callee_depth=2).get(func_ea, "")
        relevant_lines = []
        if ident:
            for line in ann.splitlines():
                if ident in line:
                    relevant_lines.append(line)
        if not relevant_lines:
            relevant_lines = ann.splitlines()
        text = "\n".join(relevant_lines) + ("\n" if relevant_lines else "")
        try:
            ida_kernwin.set_clipboard(text)
            ida_kernwin.info(f"{PLUGIN_NAME}: Copied PTN lines to clipboard.")
        except Exception:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Could not set clipboard; showing in a dialog.")
            ida_kernwin.info(text)
        return 1
    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class DumpAsmCtxActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        global g_dump_in_progress, g_multi_dump_active
        widget = ctx.widget
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return 1
        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Not available for this function.")
            return 1
        start_func_ea = vu.cfunc.entry_ea
        start_func_name = ida_funcs.get_func_name(start_func_ea) or f"sub_{start_func_ea:X}"
        with g_dump_lock:
            if start_func_ea in g_dump_in_progress:
                ida_kernwin.warning(f"{PLUGIN_NAME}: Operation already running for {start_func_name}.")
                return 1
            if g_multi_dump_active:
                ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function operation is currently running.")
                return 1
            g_dump_in_progress.add(start_func_ea)

        input_results = {"caller_depth": -1, "callee_depth": -1, "output_file": None, "xref_types": None, "max_chars": 0}
        input_container = [input_results]
        def get_inputs_main(container):
            c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
            if c_depth is None: return 0
            container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0
            ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
            if ca_depth is None: return 0
            container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0
            xref_types_str = ida_kernwin.ask_str("all", 0, "Enter comma-separated xref types to include (or 'all'):\n"
                                                         "direct_call,indirect_call,data_ref,immediate_ref,tail_call_push_ret,virtual_call,jump_table")
            if xref_types_str is None: return 0
            if xref_types_str.strip().lower() == 'all':
                container[0]["xref_types"] = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
            else:
                container[0]["xref_types"] = set([t.strip() for t in xref_types_str.split(',') if t.strip()])
            m_chars = ida_kernwin.ask_long(0, "Enter maximum characters for the output file (0 for no limit)")
            if m_chars is None: return 0
            container[0]["max_chars"] = int(m_chars) if m_chars >= 0 else 0
            default_filename = re.sub(r'[<>:"/\\|?*]', '_', f"{start_func_name}_asm_callers{c_depth}_callees{ca_depth}.asm")
            output_file = ida_kernwin.ask_file(True, default_filename, "Select Output ASM File")
            if not output_file: return 0
            container[0]["output_file"] = output_file
            return 1
        sync_status = ida_kernwin.execute_sync(lambda: get_inputs_main(input_container), ida_kernwin.MFF_WRITE)
        final_inputs = input_container[0]
        caller_depth = final_inputs["caller_depth"]
        callee_depth = final_inputs["callee_depth"]
        output_file_path = final_inputs["output_file"]
        xref_types = final_inputs["xref_types"]
        max_chars = final_inputs["max_chars"]
        if sync_status != 1 or caller_depth < 0 or callee_depth < 0 or not output_file_path or not xref_types:
            with g_dump_lock:
                g_dump_in_progress.discard(start_func_ea)
            return 1
        task_thread = threading.Thread(target=dump_task, args=(set([start_func_ea]), caller_depth, callee_depth, output_file_path, 'asm', xref_types, max_chars))
        task_thread.start()
        return 1
    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu and vu.cfunc:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

def perform_multi_dump(mode):
    global g_dump_in_progress, g_multi_dump_active
    with g_dump_lock:
        if g_multi_dump_active:
            ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function operation is already running.")
            return
        if g_dump_in_progress:
            ida_kernwin.warning(f"{PLUGIN_NAME}: One or more single function operations are running.")
            return
        g_multi_dump_active = True

    input_results = {"start_eas": set(), "caller_depth": -1, "callee_depth": -1, "output_file": None, "xref_types": None, "max_chars": 0}
    input_container = [input_results]

    def get_multi_inputs_main(container, mode):
        func_list_str = ida_kernwin.ask_str("", 0, "Enter comma-separated function names or addresses (e.g., sub_123, 0x401000, MyFunc)")
        if not func_list_str:
            return 0
        start_eas = set()
        unresolved = []
        items = [item.strip() for item in func_list_str.split(',') if item.strip()]
        if not items:
            ida_kernwin.warning(f"{PLUGIN_NAME}: No function names or addresses provided.")
            return 0
        for item in items:
            ea = idaapi.BADADDR
            if item.lower().startswith("0x"):
                try:
                    ea = int(item, 16)
                except ValueError:
                    pass
            elif item.isdigit():
                try:
                    ea = int(item)
                except ValueError:
                    pass
            if ea == idaapi.BADADDR:
                ea = ida_name.get_name_ea(idaapi.BADADDR, item)
            if ea != idaapi.BADADDR and ida_funcs.get_func(ea):
                start_eas.add(ea)
            else:
                unresolved.append(item)
        if unresolved:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Could not resolve or find functions:\n" + "\n".join(unresolved))
        if not start_eas:
            ida_kernwin.warning(f"{PLUGIN_NAME}: No valid functions found.")
            return 0
        container[0]["start_eas"] = start_eas
        c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
        if c_depth is None: return 0
        container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0
        ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
        if ca_depth is None: return 0
        container[0]["callee_depth"] = int(ca_depth) if c_depth >= 0 else 0
        xref_types_str = ida_kernwin.ask_str("all", 0, "Enter comma-separated xref types to include (or 'all'):\n"
                                                     "direct_call,indirect_call,data_ref,immediate_ref,tail_call_push_ret,virtual_call,jump_table")
        if xref_types_str is None:
            return 0
        if xref_types_str.strip().lower() == 'all':
            container[0]["xref_types"] = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
        else:
            container[0]["xref_types"] = set([t.strip() for t in xref_types_str.split(',') if t.strip()])
        m_chars = ida_kernwin.ask_long(0, "Enter maximum characters for the output file (0 for no limit)")
        if m_chars is None: return 0
        container[0]["max_chars"] = int(m_chars) if m_chars >= 0 else 0
        first_func_ea = sorted(list(start_eas))[0]
        first_func_name = ida_funcs.get_func_name(first_func_ea) or f"sub_{first_func_ea:X}"
        if mode == 'code':
            default_filename = f"multi_dump_{first_func_name}_etc_callers{c_depth}_callees{ca_depth}.c"
            title = "Select Output C File"
        elif mode == 'ptn':
            default_filename = f"multi_ptn_{first_func_name}_etc_callers{c_depth}_callees{ca_depth}.ptn"
            title = "Select Output PTN File"
        elif mode == 'asm':
            default_filename = f"multi_asm_{first_func_name}_etc_callers{c_depth}_callees{ca_depth}.asm"
            title = "Select Output ASM File"
        else:
            default_filename = f"multi_graph_{first_func_name}_etc_callers{c_depth}_callees{ca_depth}.dot"
            title = "Select Output DOT File"
        default_filename = re.sub(r'[<>:"/\\|?*]', '_', default_filename)
        output_file = ida_kernwin.ask_file(True, default_filename, title)
        if not output_file: return 0
        container[0]["output_file"] = output_file
        return 1

    sync_status = ida_kernwin.execute_sync(lambda: get_multi_inputs_main(input_container, mode), ida_kernwin.MFF_WRITE)
    final_inputs = input_container[0]
    start_eas = final_inputs["start_eas"]
    caller_depth = final_inputs["caller_depth"]
    callee_depth = final_inputs["callee_depth"]
    output_file_path = final_inputs["output_file"]
    xref_types = final_inputs["xref_types"]
    max_chars = final_inputs["max_chars"]
    if sync_status != 1 or not start_eas or caller_depth < 0 or callee_depth < 0 or not output_file_path or (mode != 'ptn' and not xref_types):
        with g_dump_lock:
            g_multi_dump_active = False
        return
    task_thread = threading.Thread(target=dump_task, args=(start_eas, caller_depth, callee_depth, output_file_path, mode, xref_types or set(), max_chars))
    task_thread.start()

class DumpCodeMultiActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        perform_multi_dump('code')
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DumpDotMultiActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        perform_multi_dump('graph')
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DumpPTNMultiActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        perform_multi_dump('ptn')
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DumpAsmMultiActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        perform_multi_dump('asm')
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DumpHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            try:
                ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_ID_CTX, "Dump code/", ida_kernwin.SETMENU_INS)
                ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_ID_DOT_CTX, "Dump code/", ida_kernwin.SETMENU_INS)
                ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_ID_PTN_CTX, "Dump code/", ida_kernwin.SETMENU_INS)
                ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_ID_PTN_COPY_CTX, "Dump code/", ida_kernwin.SETMENU_INS)
                ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_ID_ASM_CTX, "Dump code/", ida_kernwin.SETMENU_INS)
            except Exception:
                traceback.print_exc()

class CodeDumperPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_FIX
    comment = "Dumps decompiled code, DOT graphs, PTN provenance, and assembly"
    help = "Use Edit->Plugins->CodeDumper, or right-click in Pseudocode view"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""
    hooks = None

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        action_desc_ctx = ida_kernwin.action_desc_t(ACTION_ID_CTX, ACTION_LABEL_CTX, DumpCtxActionHandler(), self.wanted_hotkey, ACTION_TOOLTIP_CTX, 199)
        if not ida_kernwin.register_action(action_desc_ctx):
            return idaapi.PLUGIN_SKIP
        action_desc_dot_ctx = ida_kernwin.action_desc_t(ACTION_ID_DOT_CTX, ACTION_LABEL_DOT_CTX, DumpDotCtxActionHandler(), self.wanted_hotkey, ACTION_TOOLTIP_DOT_CTX, 199)
        if not ida_kernwin.register_action(action_desc_dot_ctx):
            ida_kernwin.unregister_action(ACTION_ID_CTX)
            return idaapi.PLUGIN_SKIP
        action_desc_ptn_ctx = ida_kernwin.action_desc_t(ACTION_ID_PTN_CTX, ACTION_LABEL_PTN_CTX, DumpPTNCtxActionHandler(), self.wanted_hotkey, ACTION_TOOLTIP_PTN_CTX, 199)
        if not ida_kernwin.register_action(action_desc_ptn_ctx):
            ida_kernwin.unregister_action(ACTION_ID_CTX); ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            return idaapi.PLUGIN_SKIP
        action_desc_ptn_copy_ctx = ida_kernwin.action_desc_t(ACTION_ID_PTN_COPY_CTX, ACTION_LABEL_PTN_COPY_CTX, CopyPTNVarCtxActionHandler(), self.wanted_hotkey, ACTION_TOOLTIP_PTN_COPY_CTX, 199)
        if not ida_kernwin.register_action(action_desc_ptn_copy_ctx):
            ida_kernwin.unregister_action(ACTION_ID_CTX); ida_kernwin.unregister_action(ACTION_ID_DOT_CTX); ida_kernwin.unregister_action(ACTION_ID_PTN_CTX)
            return idaapi.PLUGIN_SKIP
        action_desc_asm_ctx = ida_kernwin.action_desc_t(ACTION_ID_ASM_CTX, ACTION_LABEL_ASM_CTX, DumpAsmCtxActionHandler(), self.wanted_hotkey, ACTION_TOOLTIP_ASM_CTX, 199)
        if not ida_kernwin.register_action(action_desc_asm_ctx):
            ida_kernwin.unregister_action(ACTION_ID_CTX); ida_kernwin.unregister_action(ACTION_ID_DOT_CTX); ida_kernwin.unregister_action(ACTION_ID_PTN_CTX); ida_kernwin.unregister_action(ACTION_ID_PTN_COPY_CTX)
            return idaapi.PLUGIN_SKIP

        action_desc_code_multi = ida_kernwin.action_desc_t(ACTION_ID_CODE_MULTI, ACTION_LABEL_CODE_MULTI, DumpCodeMultiActionHandler(), None, ACTION_TOOLTIP_CODE_MULTI, 199)
        if not ida_kernwin.register_action(action_desc_code_multi):
            ida_kernwin.unregister_action(ACTION_ID_CTX); ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            ida_kernwin.unregister_action(ACTION_ID_PTN_CTX); ida_kernwin.unregister_action(ACTION_ID_PTN_COPY_CTX); ida_kernwin.unregister_action(ACTION_ID_ASM_CTX)
            return idaapi.PLUGIN_SKIP

        action_desc_dot_multi = ida_kernwin.action_desc_t(ACTION_ID_DOT_MULTI, ACTION_LABEL_DOT_MULTI, DumpDotMultiActionHandler(), None, ACTION_TOOLTIP_DOT_MULTI, 199)
        if not ida_kernwin.register_action(action_desc_dot_multi):
            ida_kernwin.unregister_action(ACTION_ID_CTX); ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            ida_kernwin.unregister_action(ACTION_ID_PTN_CTX); ida_kernwin.unregister_action(ACTION_ID_PTN_COPY_CTX)
            ida_kernwin.unregister_action(ACTION_ID_CODE_MULTI); ida_kernwin.unregister_action(ACTION_ID_ASM_CTX)
            return idaapi.PLUGIN_SKIP

        action_desc_ptn_multi = ida_kernwin.action_desc_t(ACTION_ID_PTN_MULTI, ACTION_LABEL_PTN_MULTI, DumpPTNMultiActionHandler(), None, ACTION_TOOLTIP_PTN_MULTI, 199)
        if not ida_kernwin.register_action(action_desc_ptn_multi):
            ida_kernwin.unregister_action(ACTION_ID_CTX); ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            ida_kernwin.unregister_action(ACTION_ID_PTN_CTX); ida_kernwin.unregister_action(ACTION_ID_PTN_COPY_CTX)
            ida_kernwin.unregister_action(ACTION_ID_CODE_MULTI); ida_kernwin.unregister_action(ACTION_ID_DOT_MULTI); ida_kernwin.unregister_action(ACTION_ID_ASM_CTX)
            return idaapi.PLUGIN_SKIP

        action_desc_asm_multi = ida_kernwin.action_desc_t(ACTION_ID_ASM_MULTI, ACTION_LABEL_ASM_MULTI, DumpAsmMultiActionHandler(), None, ACTION_TOOLTIP_ASM_MULTI, 199)
        if not ida_kernwin.register_action(action_desc_asm_multi):
            ida_kernwin.unregister_action(ACTION_ID_CTX); ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            ida_kernwin.unregister_action(ACTION_ID_PTN_CTX); ida_kernwin.unregister_action(ACTION_ID_PTN_COPY_CTX)
            ida_kernwin.unregister_action(ACTION_ID_CODE_MULTI); ida_kernwin.unregister_action(ACTION_ID_DOT_MULTI); ida_kernwin.unregister_action(ACTION_ID_PTN_MULTI); ida_kernwin.unregister_action(ACTION_ID_ASM_CTX)
            return idaapi.PLUGIN_SKIP

        ida_kernwin.attach_action_to_menu(MENU_PATH_MULTI, ACTION_ID_CODE_MULTI, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu(MENU_PATH_MULTI, ACTION_ID_DOT_MULTI, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu(MENU_PATH_MULTI, ACTION_ID_PTN_MULTI, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu(MENU_PATH_MULTI, ACTION_ID_ASM_MULTI, ida_kernwin.SETMENU_APP)

        self.hooks = DumpHooks()
        if not self.hooks.hook():
            ida_kernwin.unregister_action(ACTION_ID_CTX); ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            ida_kernwin.unregister_action(ACTION_ID_PTN_CTX); ida_kernwin.unregister_action(ACTION_ID_PTN_COPY_CTX)
            ida_kernwin.unregister_action(ACTION_ID_CODE_MULTI); ida_kernwin.unregister_action(ACTION_ID_DOT_MULTI); ida_kernwin.unregister_action(ACTION_ID_PTN_MULTI); ida_kernwin.unregister_action(ACTION_ID_ASM_MULTI); ida_kernwin.unregister_action(ACTION_ID_ASM_CTX)
            self.hooks = None
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.hooks:
            try:
                self.hooks.unhook()
            except Exception:
                pass
            self.hooks = None
        try: ida_kernwin.detach_action_from_menu(MENU_PATH_MULTI, ACTION_ID_CODE_MULTI)
        except Exception: pass
        try: ida_kernwin.detach_action_from_menu(MENU_PATH_MULTI, ACTION_ID_DOT_MULTI)
        except Exception: pass
        try: ida_kernwin.detach_action_from_menu(MENU_PATH_MULTI, ACTION_ID_PTN_MULTI)
        except Exception: pass
        try: ida_kernwin.detach_action_from_menu(MENU_PATH_MULTI, ACTION_ID_ASM_MULTI)
        except Exception: pass
        for act in [ACTION_ID_CTX, ACTION_ID_DOT_CTX, ACTION_ID_PTN_CTX, ACTION_ID_PTN_COPY_CTX, ACTION_ID_CODE_MULTI, ACTION_ID_DOT_MULTI, ACTION_ID_PTN_MULTI, ACTION_ID_ASM_CTX, ACTION_ID_ASM_MULTI]:
            try: ida_kernwin.unregister_action(act)
            except Exception: pass
        with g_dump_lock:
            g_dump_in_progress.clear()
            global g_multi_dump_active
            g_multi_dump_active = False

def PLUGIN_ENTRY():
    return CodeDumperPlugin()
