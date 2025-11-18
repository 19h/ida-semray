# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

ConfT = str  # 'low' | 'med' | 'high'

@dataclass
class ArgUse:
    cs_ea: int
    callee_ea: Optional[int]
    arg_index: int
    base_kind: str                 # 'L' | 'P' | 'G' | 'U' (unknown)
    base_id: int                   # lvar_idx | param_idx | global_ea | -1
    base_name: str = ""
    off: Optional[int] = None      # bytes
    length: Optional[int] = None   # bytes
    mode: str = ""                 # '', '&', '*'
    cast: Optional[str] = None
    conf: ConfT = "med"

@dataclass
class Alias:
    dst_kind: str                  # 'L' or 'P'
    dst_id: int
    dst_name: str
    src_kind: str                  # 'L' | 'P' | 'G' | 'U'
    src_id: int
    src_name: str = ""
    off: Optional[int] = None
    length: Optional[int] = None
    mode: str = "&"
    cast: Optional[str] = None
    conf: ConfT = "med"

@dataclass
class GlobalAccess:
    ea: int                        # global base EA
    off: Optional[int]             # byte offset into global, if known
    length: Optional[int]          # byte length, if known
    kind: str                      # 'R' or 'W'
    cs_ea: int = 0                 # code-site EA for this access (per-instruction correlation)

@dataclass
class FunctionSummary:
    func_ea: int
    func_name: str
    params: Dict[int, str] = field(default_factory=dict)  # pidx -> name
    locals: Dict[int, str] = field(default_factory=dict)  # lidx -> name
    arguses: List[ArgUse] = field(default_factory=list)
    aliases: List[Alias] = field(default_factory=list)
    globals: List[GlobalAccess] = field(default_factory=list)

class PTNEmitter:
    def __init__(self, summaries: Dict[int, FunctionSummary]):
        self.summaries = summaries
        self._fid_by_ea: Dict[int, str] = {}
        self._ea_by_fid: Dict[str, int] = {}
        self._name_by_ea: Dict[int, str] = {ea: fs.func_name for ea, fs in summaries.items()}
        self._assign_fids()

    def _assign_fids(self) -> None:
        for n, ea in enumerate(sorted(self.summaries.keys())):
            fid = f"F{n+1}"
            self._fid_by_ea[ea] = fid
            self._ea_by_fid[fid] = ea

    def _fid(self, ea: int) -> str:
        return self._fid_by_ea.get(ea, f"F?")

    @staticmethod
    def _fmt_slice(off: Optional[int], length: Optional[int]) -> str:
        if off is None and length is None:
            return ""
        if off is None and length is not None:
            return f"@[?:0x{length:X}]"
        if off is not None and length is None:
            return f"@[0x{off:X}:?]"
        return f"@[0x{off:X}:0x{length:X}]"

    @staticmethod
    def _fmt_meta(meta: Dict[str, object]) -> str:
        if not meta:
            return ""
        parts = []
        for k, v in meta.items():
            if isinstance(v, int):
                if k in ("cs",):
                    parts.append(f"{k}=0x{v:X}")
                else:
                    parts.append(f"{k}={v}")
            else:
                parts.append(f"{k}={v}")
        return " {" + ",".join(parts) + "}"

    def _fmt_node_L(self, fid: str, lidx: int, off: Optional[int], length: Optional[int],
                    mode: str, cast: Optional[str], name: str = "", meta: Optional[Dict[str, object]] = None) -> str:
        s = f"L({fid},{lidx}){self._fmt_slice(off, length)}{mode}"
        if cast:
            s += f":({cast})"
        if meta:
            s += self._fmt_meta(meta)
        return s

    def _fmt_node_P(self, fid: str, pidx: int, off: Optional[int], length: Optional[int],
                    mode: str, cast: Optional[str], meta: Optional[Dict[str, object]] = None) -> str:
        s = f"P({fid},{pidx}){self._fmt_slice(off, length)}{mode}"
        if cast:
            s += f":({cast})"
        if meta:
            s += self._fmt_meta(meta)
        return s

    def _fmt_node_A(self, fid: str, arg_index: int, meta: Optional[Dict[str, object]] = None) -> str:
        s = f"A({fid},{arg_index})"
        if meta:
            s += self._fmt_meta(meta)
        return s

    def _fmt_node_G(self, ea: int, off: Optional[int], length: Optional[int], meta: Optional[Dict[str, object]] = None) -> str:
        s = f"G(0x{ea:X}){self._fmt_slice(off, length)}"
        if meta:
            s += self._fmt_meta(meta)
        return s

    def _fmt_node_F(self, fid: str, meta: Optional[Dict[str, object]] = None) -> str:
        s = f"F({fid})"
        if meta:
            s += self._fmt_meta(meta)
        return s

    def _dict_header(self, restrict_eas: Optional[Set[int]] = None) -> str:
        eas = sorted((restrict_eas or set(self.summaries.keys())))
        parts = []
        for ea in eas:
            fid = self._fid(ea)
            name = self._name_by_ea.get(ea, "")
            if name:
                parts.append(f"{fid}=0x{ea:X},{name}")
            else:
                parts.append(f"{fid}=0x{ea:X}")
        return "D:" + ";".join(parts)

    def _build_param_forward(self) -> Dict[Tuple[int, int], List[Tuple[int, int, Dict[str, object]]]]:
        fwd: Dict[Tuple[int, int], List[Tuple[int, int, Dict[str, object]]]] = {}
        for fea, fs in self.summaries.items():
            for au in fs.arguses:
                if au.base_kind == "P" and au.callee_ea is not None:
                    key = (fea, au.base_id)
                    lst = fwd.setdefault(key, [])
                    meta = {}
                    if au.off is not None:
                        meta["off"] = au.off
                    if au.length is not None:
                        meta["len"] = au.length
                    if au.mode:
                        meta["mode"] = au.mode
                    if au.cs_ea:
                        meta["cs"] = au.cs_ea
                    if au.conf:
                        meta["conf"] = au.conf
                    lst.append((au.callee_ea, au.arg_index, meta))
        return fwd

    def _build_incoming_map(self) -> Dict[Tuple[int, int], List[Dict[str, object]]]:
        inc: Dict[Tuple[int, int], List[Dict[str, object]]] = {}
        for caller_ea, fs in self.summaries.items():
            for au in fs.arguses:
                if au.callee_ea is None:
                    continue
                key = (au.callee_ea, au.arg_index)
                lst = inc.setdefault(key, [])
                lst.append({
                    "caller_ea": caller_ea,
                    "origin_kind": au.base_kind,
                    "origin_id": au.base_id,
                    "origin_name": au.base_name,
                    "off": au.off,
                    "length": au.length,
                    "mode": au.mode,
                    "cast": au.cast,
                    "conf": au.conf,
                    "cs_ea": au.cs_ea,
                })
        return inc

    def emit_ptn(self, start_eas: Set[int], callee_depth: int, restrict_eas: Optional[Set[int]] = None) -> str:
        lines: List[str] = []
        target_set = restrict_eas or start_eas or set(self.summaries.keys())
        lines.append("#PTN v0")
        lines.append(self._dict_header(target_set))

        param_forward = self._build_param_forward()
        incoming_map = self._build_incoming_map()
        visited_line_keys: Set[str] = set()

        def add_line(s: str) -> None:
            if s not in visited_line_keys:
                visited_line_keys.add(s)
                lines.append(s)

        for fea in sorted(target_set):
            fs = self.summaries.get(fea)
            if not fs:
                continue
            fid = self._fid(fea)
            add_line(f"D:{fid}=0x{fea:X},{fs.func_name}")
            for al in fs.aliases:
                dst = f"{al.dst_kind}({fid},{al.dst_id})"
                src = self._fmt_origin(al.src_kind, fea, al.src_id, al.src_name, al.off, al.length, al.mode, al.cast, {"conf": al.conf})
                add_line(f"A:{dst}:={src}")

        for (callee_ea, pidx), entries in incoming_map.items():
            if callee_ea not in target_set:
                continue
            callee_fid = self._fid(callee_ea)
            for ent in entries:
                caller_ea = ent["caller_ea"]
                origin = self._fmt_origin(ent["origin_kind"], caller_ea, ent["origin_id"], ent["origin_name"],
                                          ent["off"], ent["length"], ent["mode"], ent["cast"],
                                          {"conf": ent["conf"], "cs": ent["cs_ea"], "caller": self._fid(caller_ea)})
                dst = self._fmt_node_P(callee_fid, pidx, None, None, "", None, None)
                add_line(f"I:{origin} -> {dst}")

        by_func: Dict[int, List[ArgUse]] = {}
        for fea, fs in self.summaries.items():
            by_func.setdefault(fea, []).extend(fs.arguses)

        for fea in sorted(target_set):
            uses = by_func.get(fea, [])
            for au in uses:
                if au.callee_ea is None:
                    continue
                origin = self._fmt_origin(au.base_kind, fea, au.base_id, au.base_name, au.off, au.length, au.mode, au.cast,
                                          {"conf": au.conf, "cs": au.cs_ea} if au.cs_ea else {"conf": au.conf})
                fid_to = self._fid(au.callee_ea)
                add_line(f"E:{origin} -> {self._fmt_node_A(fid_to, au.arg_index)}")

                frontier: List[Tuple[int, int, int]] = []
                if au.base_kind in ("L", "P"):
                    frontier.append((au.callee_ea, au.arg_index, 1))
                depth_seen: Set[Tuple[int, int]] = set()
                while frontier:
                    cur_fea, pidx, depth = frontier.pop()
                    if depth >= callee_depth:
                        continue
                    key = (cur_fea, pidx)
                    if key in depth_seen:
                        continue
                    depth_seen.add(key)
                    for (next_callee_ea, next_argk, meta) in param_forward.get(key, []):
                        fid_mid = self._fid(cur_fea)
                        fid_next = self._fid(next_callee_ea)
                        add_line(f"E:{origin} -> A({fid_mid},{pidx}) -> A({fid_next},{next_argk})")
                        frontier.append((next_callee_ea, next_argk, depth + 1))

        writers: Dict[int, Set[int]] = {}
        readers: Dict[int, Set[int]] = {}
        for fea, fs in self.summaries.items():
            for ga in fs.globals:
                if ga.kind == "W":
                    writers.setdefault(ga.ea, set()).add(fea)
                elif ga.kind == "R":
                    readers.setdefault(ga.ea, set()).add(fea)
        for gea, ws in writers.items():
            rs = readers.get(gea, set())
            for fw in sorted(ws):
                for fr in sorted(rs):
                    if fw in target_set or fr in target_set:
                        lines.append("G:" + self._fmt_node_F(self._fid(fw)) + " -> " +
                                     self._fmt_node_G(gea, None, None, {}) + " -> " +
                                     self._fmt_node_F(self._fid(fr)))

        return "\
".join(lines) + "\
"

    def _fmt_origin(self, kind: str, fea: int, idx: int, name: str,
                    off: Optional[int], length: Optional[int], mode: str, cast: Optional[str],
                    meta: Dict[str, object]) -> str:
        fid = self._fid(fea)
        m = dict(meta)
        if name:
            m["name"] = name
        if kind == "L":
            return self._fmt_node_L(fid, max(idx, -1), off, length, mode, cast, name, m)
        if kind == "P":
            return self._fmt_node_P(fid, max(idx, -1), off, length, mode, cast, m)
        if kind == "G":
            return self._fmt_node_G(idx, off, length, m)
        return "U" + self._fmt_meta(m)

    def per_function_annotations(self, callee_depth: int) -> Dict[int, str]:
        param_forward = self._build_param_forward()
        incoming_map = self._build_incoming_map()
        out: Dict[int, str] = {}
        for fea, fs in self.summaries.items():
            fid = self._fid(fea)
            lines: List[str] = []
            lines.append(f"// @PTN D:{fid}=0x{fea:X},{fs.func_name}")
            for al in fs.aliases:
                dst = f"{al.dst_kind}({fid},{al.dst_id})"
                src = self._fmt_origin(al.src_kind, fea, al.src_id, al.src_name, al.off, al.length, al.mode, al.cast, {"conf": al.conf})
                lines.append(f"// @PTN A:{dst}:={src}")
            for (callee_ea, pidx), entries in incoming_map.items():
                if callee_ea != fea:
                    continue
                for ent in entries:
                    caller_ea = ent["caller_ea"]
                    origin = self._fmt_origin(ent["origin_kind"], caller_ea, ent["origin_id"], ent["origin_name"],
                                              ent["off"], ent["length"], ent["mode"], ent["cast"],
                                              {"conf": ent["conf"], "cs": ent["cs_ea"], "caller": self._fid(caller_ea)})
                    dst = self._fmt_node_P(fid, pidx, None, None, "", None, None)
                    lines.append(f"// @PTN I:{origin} -> {dst}")
            for au in fs.arguses:
                if au.callee_ea is None:
                    continue
                origin = self._fmt_origin(au.base_kind, fea, au.base_id, au.base_name, au.off, au.length, au.mode, au.cast,
                                          {"conf": au.conf, "cs": au.cs_ea} if au.cs_ea else {"conf": au.conf})
                lines.append(f"// @PTN E:{origin} -> {self._fmt_node_A(self._fid(au.callee_ea), au.arg_index)}")
                if callee_depth > 1 and au.base_kind in ("L", "P"):
                    key = (au.callee_ea, au.arg_index)
                    for (nc_ea, narg, meta) in param_forward.get(key, []):
                        lines.append(f"// @PTN E:{origin} -> A({self._fid(au.callee_ea)},{au.arg_index}) -> A({self._fid(nc_ea)},{narg})")
            for ga in fs.globals:
                if ga.kind == "W":
                    lines.append(f"// @PTN G:{self._fmt_node_F(fid)} -> {self._fmt_node_G(ga.ea, ga.off, ga.length)}")
                elif ga.kind == "R":
                    lines.append(f"// @PTN G:{self._fmt_node_G(ga.ea, ga.off, ga.length)} -> {self._fmt_node_F(fid)}")
            out[fea] = "\
".join(lines) + ("\
" if lines else "")
        return out

    def per_instruction_hints(self, callee_depth: int = 1) -> Dict[int, Dict[int, List[str]]]:
        hints: Dict[int, Dict[int, List[str]]] = {}
        param_forward = self._build_param_forward()
        for fea, fs in self.summaries.items():
            for au in fs.arguses:
                if not au.cs_ea or au.callee_ea is None:
                    continue
                origin = self._fmt_origin(au.base_kind, fea, au.base_id, au.base_name, au.off, au.length, au.mode, au.cast,
                                          {"conf": au.conf})
                fid_to = self._fid(au.callee_ea)
                line0 = f"@PTN E:{origin} -> {self._fmt_node_A(fid_to, au.arg_index)}"
                hints.setdefault(fea, {}).setdefault(au.cs_ea, []).append(line0)

                if callee_depth > 1 and au.base_kind in ("L", "P"):
                    frontier: List[Tuple[int, int, int]] = [(au.callee_ea, au.arg_index, 1)]
                    depth_seen: Set[Tuple[int, int]] = set()
                    while frontier:
                        cur_fea, pidx, depth = frontier.pop()
                        if depth >= callee_depth:
                            continue
                        key = (cur_fea, pidx)
                        if key in depth_seen:
                            continue
                        depth_seen.add(key)
                        for (next_callee_ea, next_argk, meta) in param_forward.get(key, []):
                            fid_mid = self._fid(cur_fea)
                            fid_next = self._fid(next_callee_ea)
                            hints.setdefault(fea, {}).setdefault(au.cs_ea, []).append(
                                f"@PTN E:{origin} -> A({fid_mid},{pidx}) -> A({fid_next},{next_argk})"
                            )
                            frontier.append((next_callee_ea, next_argk, depth + 1))
        for fea, fs in self.summaries.items():
            fid = self._fid(fea)
            for ga in fs.globals:
                if not ga.cs_ea:
                    continue
                if ga.kind == "W":
                    line = f"@PTN G:{self._fmt_node_F(fid)} -> {self._fmt_node_G(ga.ea, ga.off, ga.length)}"
                else:
                    line = f"@PTN G:{self._fmt_node_G(ga.ea, ga.off, ga.length)} -> {self._fmt_node_F(fid)}"
                hints.setdefault(fea, {}).setdefault(ga.cs_ea, []).append(line)
        return hints

    def emit_ptn_json(self, start_eas: Set[int], callee_depth: int, restrict_eas: Optional[Set[int]] = None) -> str:
        target_set = sorted(list(restrict_eas or start_eas or set(self.summaries.keys())))
        param_forward = self._build_param_forward()
        incoming_map = self._build_incoming_map()

        obj: Dict[str, object] = {
            "version": "0",
            "dict": [{"fid": self._fid(ea), "ea": f"0x{ea:X}", "name": self._name_by_ea.get(ea, "")} for ea in target_set],
            "aliases": [],
            "calls": [],
            "globals": [],
            "inbound": []
        }

        for fea in target_set:
            fs = self.summaries.get(fea)
            if not fs:
                continue
            fid = self._fid(fea)
            for al in fs.aliases:
                obj["aliases"].append({
                    "func": {"fid": fid, "ea": f"0x{fea:X}"},
                    "dst": {"kind": al.dst_kind, "id": al.dst_id, "name": al.dst_name},
                    "src": {"kind": al.src_kind, "id": al.src_id, "name": al.src_name,
                            "off": al.off, "len": al.length, "mode": al.mode, "cast": al.cast},
                    "conf": al.conf
                })

        for fea in target_set:
            fs = self.summaries.get(fea)
            if not fs:
                continue
            for au in fs.arguses:
                if au.callee_ea is None:
                    continue
                obj["calls"].append({
                    "caller": {"fid": self._fid(fea), "ea": f"0x{fea:X}"},
                    "cs_ea": f"0x{au.cs_ea:X}" if au.cs_ea else None,
                    "origin": {"kind": au.base_kind, "id": au.base_id, "name": au.base_name,
                               "off": au.off, "len": au.length, "mode": au.mode, "cast": au.cast, "conf": au.conf},
                    "callee": {"fid": self._fid(au.callee_ea), "ea": f"0x{au.callee_ea:X}"},
                    "arg_index": au.arg_index
                })

        for fea in target_set:
            fs = self.summaries.get(fea)
            if not fs:
                continue
            for ga in fs.globals:
                obj["globals"].append({
                    "func": {"fid": self._fid(fea), "ea": f"0x{fea:X}"},
                    "op": ga.kind,
                    "global_ea": f"0x{ga.ea:X}",
                    "off": ga.off, "len": ga.length,
                    "cs_ea": f"0x{ga.cs_ea:X}" if ga.cs_ea else None
                })

        for (callee_ea, pidx), entries in incoming_map.items():
            if callee_ea not in target_set:
                continue
            for ent in entries:
                obj["inbound"].append({
                    "to": {"fid": self._fid(callee_ea), "ea": f"0x{callee_ea:X}", "param": pidx},
                    "from": {"fid": self._fid(ent["caller_ea"]), "ea": f"0x{ent['caller_ea']:X}"},
                    "origin": {"kind": ent["origin_kind"], "id": ent["origin_id"], "name": ent["origin_name"],
                               "off": ent["off"], "len": ent["length"], "mode": ent["mode"], "cast": ent["cast"], "conf": ent["conf"]},
                    "cs_ea": f"0x{ent['cs_ea']:X}" if ent["cs_ea"] else None
                })

        return json.dumps(obj, indent=2) + "\
"
