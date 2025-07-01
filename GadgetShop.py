#!/usr/bin/env python3
import re
import sys
import argparse
from pathlib import Path
from struct import pack
from collections import deque
from typing import Callable

# ==============================================================================
#                                CONFIGURATION
# ==============================================================================

# Registers we care about
REGS_ALL = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "al", "bl", "cl", "dl"]
REGS_32  = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]

LOW8_MAP  = {"al": "eax", "bl": "ebx", "cl": "ecx", "dl": "edx"}
LOW16_MAP = {
    "ax": "eax", "bx": "ebx", "cx": "ecx", "dx": "edx",
    "si": "esi", "di": "edi", "sp": "esp", "bp": "ebp"
}

# Offsets & addresses (to be adjusted at runtime)
OFFSET_VA        = 0x1C
ADDR_VA_IAT_OFF = 0x0
VA_IAT_ADJUST    = 0
BAD_BYTES: set  = set()

# Sentinels for emulation
SENTINELS = {
    "eax": 0x11111111, "ebx": 0x22222222, "ecx": 0x33333333,
    "edx": 0x44444444, "esi": 0x55555555, "edi": 0x66666666,
    "esp": 0x57ACADD1, "ebp": 0x88888888,
}

# Pseudo-CPU state for emulation
regs   = {r: 0 for r in REGS_32}
regs["esp"] = 0x57ACADD1
stack  = []
memory = {}  # address -> 32-bit value
UNCONTROLLED = 0xDEADBEEF

# Regex patterns (compiled once)
GADGET_LINE_RE = re.compile(r"^\s*0x[0-9A-Fa-f]{8}:")
ESP_WRITE_RE   = re.compile(r"\b(?:mov|lea)\s+esp\b|\bpop\s+esp\b", re.IGNORECASE)

PATTERNS = {
    # Anchor patterns for AutoRop step 1
    "anchor_mov_esp": re.compile(rf"\bmov\s+({'|'.join(REGS_ALL)}),\s*esp\b", re.IGNORECASE),
    "anchor_pushpop": re.compile(
        rf"\bpush\s+esp\b(?:\s*;\s*[^;]+)*\s*;\s*pop\s+({'|'.join(REGS_ALL)})\b",
        re.IGNORECASE
    ),
    # Individual instruction filters
    "pop_reg":     re.compile(rf"\bpop\s+({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "pushpop":     re.compile(
        rf"\bpush\s+({'|'.join(REGS_ALL)})\b(?:\s*;\s*[^;]+)*\s*;\s*pop\s+({'|'.join(REGS_ALL)})\b",
        re.IGNORECASE
    ),
    "inc_reg":     re.compile(rf"\binc\s+({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "dec_reg":     re.compile(rf"\bdec\s+({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "neg_reg":     re.compile(rf"\bneg\s+({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "add_rr":      re.compile(rf"\badd\s+({'|'.join(REGS_ALL)}),\s*({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "add_ri":      re.compile(rf"\badd\s+({'|'.join(REGS_ALL)}),\s*0x[0-9A-Fa-f]+\b", re.IGNORECASE),
    "sub_rr":      re.compile(rf"\bsub\s+({'|'.join(REGS_ALL)}),\s*({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "sub_ri":      re.compile(rf"\bsub\s+({'|'.join(REGS_ALL)}),\s*0x[0-9A-Fa-f]+\b", re.IGNORECASE),
    "xor_rr":      re.compile(rf"\bxor\s+({'|'.join(REGS_ALL)}),\s*\1\b", re.IGNORECASE),
    "mov_rr":      re.compile(rf"\bmov\s+({'|'.join(REGS_ALL)}),\s*({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "xchg_rr":     re.compile(rf"\bxchg\s+({'|'.join(REGS_ALL)}),\s*({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "deref_re":    re.compile(rf"\bmov\s+(?:dword\s+)?\[\s*.*?\s*\],\s*({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "mov_reg_mem": re.compile(r'\bmov\s+(' + '|'.join(REGS_ALL) + r')\s*,\s*'r'(?:dword\s+)?' +r'\[\s*(' + '|'.join(REGS_ALL) + r')(?:\s*[\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]',re.IGNORECASE),
    "push_esp_re": re.compile(
        rf"\bpush\s+esp\b(?:\s*;\s*[^;]+)*\s*;\s*pop\s+({'|'.join(REGS_ALL)})\b",
        re.IGNORECASE
    ),
    "mov_reg_esp": re.compile(rf"\bmov\s+({'|'.join(REGS_ALL)}),\s*esp\b", re.IGNORECASE),
    "lea_reg_esp": re.compile(rf"\blea\s+({'|'.join(REGS_ALL)}),\s*\[esp\]\b", re.IGNORECASE),
    "mov_mem_esp": re.compile(rf"\bmov\s+\[({'|'.join(REGS_ALL)})\],\s*esp\b", re.IGNORECASE),
    "mov_reg_memesp": re.compile(rf"\bmov\s+({'|'.join(REGS_ALL)}),\s*\[esp\]\b", re.IGNORECASE),
    "pivot_re":     re.compile(
        rf"\bxchg\s+esp\s*,\s*({'|'.join(REGS_ALL)})\b|\bxchg\s+({'|'.join(REGS_ALL)})\s*,\s*esp\b",
        re.IGNORECASE
    ),
    "xchg_mem_reg": re.compile(rf"\bxchg\s+\[({'|'.join(REGS_ALL)})\]\s*,\s*({'|'.join(REGS_ALL)})\b", re.IGNORECASE),
    "xchg_reg_mem": re.compile(rf"\bxchg\s+({'|'.join(REGS_ALL)})\s*,\s*\[({'|'.join(REGS_ALL)})\]\b", re.IGNORECASE),
}

# ==============================================================================
#                                  DATA CLASSES
# ==============================================================================

class Gadget:
    __slots__ = ("address", "instrs", "text")

    def __init__(self, line: str):
        self.text = line.rstrip()
        addr, rest = line.split(":", 1)
        self.address = addr.strip()
        rest = re.sub(r"\(\d+\s+found\)\s*$", "", rest)
        self.instrs = [i.strip().lower() for i in rest.split(";") if i.strip()]

    def __lt__(self, other):
        return len(self.instrs) < len(other.instrs)

# ==============================================================================
#                              GADGET LOADING & FILTERING
# ==============================================================================

def detect_encoding(path: Path) -> str:
    with open(path, "rb") as f:
        bom = f.read(2)
    return "utf-16" if bom in (b"\xff\xfe", b"\xfe\xff") else "latin-1"

def load_gadgets(path: Path) -> list[Gadget]:
    enc = detect_encoding(path)
    with open(path, encoding=enc, errors="ignore") as f:
        lines = [L for L in f if GADGET_LINE_RE.match(L)]
    return [Gadget(L) for L in lines]

def normalize_bad_byte(tok: str) -> str:
    t = tok.strip().lower()
    if t.startswith("\\x"):
        t = t[2:]
    if t.startswith("0x"):
        t = t[2:]
    if t.startswith("x"):
        t = t[1:]
    t = t.zfill(2)
    if not re.fullmatch(r"[0-9a-f]{2}", t):
        raise ValueError(f"Bad byte token: {tok!r}")
    return t

def chunk_address(addr: str) -> list[str]:
    h = addr[2:].lower()
    return [h[i : i + 2] for i in range(0, len(h), 2)]

def filter_bad_bytes(gadgets: list[Gadget], bad_list: list[str]) -> list[Gadget]:
    bad = {normalize_bad_byte(x) for x in bad_list}
    return [
        g for g in gadgets
        if not any(byte in bad for byte in chunk_address(g.address))
    ]

def filter_flow(gadgets: list[Gadget]) -> list[Gadget]:
    def is_flow_instr(instr: str) -> bool:
        op = instr.split()[0].lower()
        return op == "call" or op.startswith("jmp")
    return [
        g for g in gadgets
        if not any(is_flow_instr(i) for i in g.instrs)
    ]

def filter_single_ret(gadgets: list[Gadget]) -> list[Gadget]:
    retn_immed = re.compile(r"^retn(?:\s+0x[0-9a-f]+)?$")
    filtered = []
    for g in gadgets:
        if len(g.instrs) == 1 and (g.instrs[0] == "ret" or retn_immed.match(g.instrs[0])):
            continue
        filtered.append(g)
    return filtered

def filter_c2(gadgets: list[Gadget]) -> list[Gadget]:
    re_c2 = re.compile(r"^retn\s+0x[0-9a-f]+$")
    return [
        g for g in gadgets
        if not any(re_c2.match(i) for i in g.instrs)
    ]

def filter_leave(gadgets: list[Gadget]) -> list[Gadget]:
    return [
        g for g in gadgets
        if not any(instr.split()[0].lower() == "leave" for instr in g.instrs)
    ]

def dump_stage1(gadgets: list[Gadget], fname: Path) -> None:
    with open(fname, "w") as o:
        for g in sorted(gadgets):
            o.write(g.text + "\n")

# ==============================================================================
#                             GADGET CATEGORIZATION
# ==============================================================================

def find_useful(gadgets: list[Gadget], dedupe: bool = True) -> dict[str, list[Gadget]]:
    buckets = {
        "STACK ANCHOR": [],  "STACK PIVOT": [],    "POP REG": [],
        "PUSH REG/POP REG": [], "INC REG": [],    "DEC REG": [],
        "NEG REG": [],       "ADD REG,REG": [],     "ADD REG,IMM": [],
        "SUB REG,REG": [],   "SUB REG,IMM": [],     "MOV REG,REG": [],
        "MOV [REG],REG": [], "MOV REG,[REG]": [],   "LEA REG,MEM": [],
        "XCHG REG,REG": [],  "XCHG MEM,REG": [],   "XOR REG,REG": [],
    }

    for g in gadgets:
        instrs = "; ".join(g.instrs)

        if PATTERNS["pop_reg"].search(instrs):
            buckets["POP REG"].append(g)
        if PATTERNS["xor_rr"].search(instrs):
            buckets["XOR REG,REG"].append(g)
        if PATTERNS["pushpop"].search(instrs):
            buckets["PUSH REG/POP REG"].append(g)
        if PATTERNS["xchg_mem_reg"].search(instrs) or PATTERNS["xchg_reg_mem"].search(instrs):
            buckets["XCHG MEM,REG"].append(g)
        if PATTERNS["inc_reg"].search(instrs):
            buckets["INC REG"].append(g)
        if PATTERNS["dec_reg"].search(instrs):
            buckets["DEC REG"].append(g)
        if PATTERNS["add_rr"].search(instrs):
            buckets["ADD REG,REG"].append(g)
        if PATTERNS["add_ri"].search(instrs):
            buckets["ADD REG,IMM"].append(g)
        if PATTERNS["sub_rr"].search(instrs):
            buckets["SUB REG,REG"].append(g)
        if PATTERNS["sub_ri"].search(instrs):
            buckets["SUB REG,IMM"].append(g)
        if PATTERNS["mov_rr"].search(instrs):
            buckets["MOV REG,REG"].append(g)
        if PATTERNS["xchg_rr"].search(instrs):
            buckets["XCHG REG,REG"].append(g)
        if PATTERNS["deref_re"].search(instrs):
            buckets["MOV [REG],REG"].append(g)
        if PATTERNS["neg_reg"].search(instrs):
            buckets["NEG REG"].append(g)

        # Stack Anchor patterns
        if (PATTERNS["push_esp_re"].search(instrs)
            or PATTERNS["mov_reg_esp"].search(instrs)
            or PATTERNS["lea_reg_esp"].search(instrs)
            or PATTERNS["mov_mem_esp"].search(instrs)
            or PATTERNS["mov_reg_memesp"].search(instrs)
        ):
            buckets["STACK ANCHOR"].append(g)
        # Stack Pivot patterns
        if PATTERNS["pivot_re"].search(instrs):
            buckets["STACK PIVOT"].append(g)
        if PATTERNS["lea_reg_esp"].search(instrs):
            buckets["LEA REG,MEM"].append(g)
        if PATTERNS["mov_reg_mem"].search(instrs):
            buckets["MOV REG,[REG]"].append(g)

    if dedupe:
        for key in buckets:
            seen = set()
            unique = []
            for g in buckets[key]:
                seq = re.sub(r";\s*retn?.*$", "", g.text, flags=re.IGNORECASE).split(":", 1)[1].strip()
                if seq not in seen:
                    seen.add(seq)
                    unique.append(g)
            buckets[key] = unique

    for key in buckets:
        buckets[key].sort(key=lambda x: len(x.instrs), reverse=True)

    return buckets

# ==============================================================================
#                              MOVE GRAPH GENERATION
# ==============================================================================

def build_move_graph(gadgets: list[Gadget]) -> dict[str, list[tuple[str, Gadget, list[str]]]]:
    # helper to fold 8/16-bit names into their 32-bit parents
    def canonical_reg(r: str) -> str | None:
        r = r.lower()
        if r in REGS_32:
            return r
        if r in LOW8_MAP:
            return LOW8_MAP[r]
        if r in LOW16_MAP:
            return LOW16_MAP[r]
        return None

    graph: dict[str, list[tuple[str, Gadget, list[str]]]] = {r: [] for r in REGS_32}

    for g in gadgets:
        joined = "; ".join(g.instrs).lower()
        if ESP_WRITE_RE.search(joined):
            continue  # skip any gadget that writes to ESP

        # Identify destination registers clobbered by this gadget
        dest_regs = set()
        for instr in g.instrs:
            op = instr.strip().split()[0].lower()
            if op in ("pop", "mov", "xchg", "lea"):
                parts = instr.replace(",", " ").split()
                if op == "pop" and parts[1] in REGS_32:
                    dest_regs.add(parts[1])
                elif op in ("mov", "lea"):
                    dst = parts[1].strip("[],")
                    if dst in REGS_32:
                        dest_regs.add(dst)
                elif op == "xchg":
                    a, b = parts[1].rstrip(","), parts[2]
                    if a in REGS_32:
                        dest_regs.add(a)
                    if b in REGS_32:
                        dest_regs.add(b)

        # Patterns to detect moves
        move_patterns = [
            (PATTERNS["mov_rr"],     lambda m: [(m.group(2).lower(), m.group(1).lower())]),
            (PATTERNS["xchg_rr"],    lambda m: [(m.group(2).lower(), m.group(1).lower()),
                                                (m.group(1).lower(), m.group(2).lower())]),
            (PATTERNS["pushpop"],    lambda m: [(m.group(1).lower(), m.group(2).lower())]),
            (PATTERNS["lea_reg_esp"], lambda m: [(m.group(2).lower(), m.group(1).lower())]),
        ]

        for regex, extract in move_patterns:
            m = regex.search(joined)
            if not m:
                continue
            pairs = extract(m)
            for src8, dst8 in pairs:
                # fold any al/bl/cl/... into eax/ebx/ecx, etc.
                src = canonical_reg(src8)
                dst = canonical_reg(dst8)
                if src is None or dst is None:
                    continue
                # re‐map side-effects too
                se = []
                for sreg in dest_regs:
                    cr = canonical_reg(sreg)
                    if cr and cr != dst:
                        se.append(cr)
                graph[src].append((dst, g, se))

    # — prune to top-10 edges per register —
    MAX_EDGES_PER_REG = 10
    for reg, edges in graph.items():
        # each item is (dst_reg, Gadget, side_effects)
        edges.sort(key=lambda item: (len(item[1].instrs), len(item[2])))
        graph[reg] = edges[:MAX_EDGES_PER_REG]

    return graph

def find_move_paths(graph: dict[str, list], src: str, dst: str, max_depth: int = 3, max_paths: int = 100) -> list[list[tuple[str, str, Gadget, list[str]]]]:
    paths = []
    q = deque([(src, [], {src})])

    while q and len(paths) < max_paths:
        reg, path, seen = q.popleft()
        if len(path) >= max_depth:
            if reg == dst:
                paths.append(path)
            continue

        for (nxt, gadget, side) in graph.get(reg, []):
            if nxt in seen:
                continue
            new_path = path + [(reg, nxt, gadget, side)]
            if nxt == dst:
                paths.append(new_path)
            q.append((nxt, new_path, seen | {nxt}))

    paths.sort(key=lambda p: (len(p), -sum(len(step[3]) for step in p)))
    return paths

# ==============================================================================
#                              GADGET EMULATION
# ==============================================================================

def emulate_gadget(gadget: Gadget) -> None:
    for instr in gadget.instrs:
        parts = instr.strip().split(None, 1)
        op = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if op == "push":
            r = args.strip().lower()
            if r in regs:
                stack.append(regs[r])

        elif op == "pop":
            r = args.strip().lower()
            if r in regs:
                regs[r] = stack.pop() if stack else 0

        elif op == "xchg":
            a, b = [x.strip("[] ") for x in args.split(",", 1)]
            if a in regs and b in regs:
                regs[a], regs[b] = regs[b], regs[a]

        elif op == "mov":
            dst, src = [x.strip() for x in args.split(",", 1)]
            m_mem_store = re.match(r"^\[\s*([^\+\-\]]+)\s*([\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]$", dst)
            if m_mem_store and src.lower() in regs:
                base = m_mem_store.group(1).lower()
                off = int(m_mem_store.group(2).replace(" ", ""), 16) if m_mem_store.group(2) else 0
                addr = regs.get(base, 0) + off
                memory[addr] = regs[src.lower()]

            elif re.match(r"^\[\s*", src):
                m2 = re.match(r"^\[\s*([^\+\-\]]+)\s*([\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]$", src)
                if dst.lower() in regs and m2:
                    base = m2.group(1).lower()
                    off = int(m2.group(2).replace(" ", ""), 16) if m2.group(2) else 0
                    addr = regs.get(base, 0) + off
                    regs[dst.lower()] = memory.get(addr, UNCONTROLLED)

            else:
                val = None
                low8 = dst.lower() in LOW8_MAP
                low16 = dst.lower() in LOW16_MAP

                if src.lower() in regs:
                    val = regs[src.lower()]
                elif src.lower() in LOW8_MAP:
                    val = regs[LOW8_MAP[src.lower()]] & 0xFF
                elif src.lower() in LOW16_MAP:
                    val = regs[LOW16_MAP[src.lower()]] & 0xFFFF
                else:
                    try:
                        val = int(src, 16)
                    except ValueError:
                        val = None

                if val is not None:
                    if low8:
                        p = LOW8_MAP[dst.lower()]
                        regs[p] = (regs[p] & ~0xFF) | (val & 0xFF)
                    elif low16:
                        p = LOW16_MAP[dst.lower()]
                        regs[p] = (regs[p] & ~0xFFFF) | (val & 0xFFFF)
                    elif dst.lower() in regs:
                        regs[dst.lower()] = val & 0xFFFFFFFF

        elif op == "lea":
            dst, mem = [x.strip() for x in args.split(",", 1)]
            m = re.match(r"^\[\s*([^\+\-\]]+)\s*([\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]$", mem)
            if dst.lower() in regs and m:
                base = m.group(1).lower()
                off = int(m.group(2).replace(" ", ""), 16) if m.group(2) else 0
                regs[dst.lower()] = (regs.get(base, 0) + off) & 0xFFFFFFFF

        elif op in ("inc", "dec", "neg"):
            r = args.strip().lower()
            if r in regs:
                if op == "inc":
                    regs[r] = (regs[r] + 1) & 0xFFFFFFFF
                elif op == "dec":
                    regs[r] = (regs[r] - 1) & 0xFFFFFFFF
                else:  # neg
                    regs[r] = (-regs[r]) & 0xFFFFFFFF

        elif op in ("add", "sub", "and", "or", "xor"):
            dst_src = args.split(",", 1)
            if len(dst_src) != 2:
                continue
            dst = dst_src[0].strip().lower()
            src = dst_src[1].strip().lower()

            if dst not in regs and dst not in LOW8_MAP and dst not in LOW16_MAP:
                continue

            if src in regs:
                val = regs[src]
            elif src in LOW8_MAP:
                val = regs[LOW8_MAP[src]] & 0xFF
            elif src in LOW16_MAP:
                val = regs[LOW16_MAP[src]] & 0xFFFF
            else:
                try:
                    val = int(src, 16)
                except ValueError:
                    continue

            opmap = {
                "add": lambda a, b: a + b,
                "sub": lambda a, b: a - b,
                "and": lambda a, b: a & b,
                "or":  lambda a, b: a | b,
                "xor": lambda a, b: a ^ b,
            }
            res = opmap[op](regs.get(dst, 0), val) & 0xFFFFFFFF

            if dst in LOW8_MAP:
                p = LOW8_MAP[dst]
                regs[p] = (regs[p] & ~0xFF) | (res & 0xFF)
            elif dst in LOW16_MAP:
                p = LOW16_MAP[dst]
                regs[p] = (regs[p] & ~0xFFFF) | (res & 0xFFFF)
            else:
                regs[dst] = res

        elif op in ("shr", "shl", "sar"):
            dst_n = args.split(",", 1)[0].strip().lower()
            if dst_n not in regs:
                continue
            try:
                cnt = int(args.split(",", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            val = regs[dst_n] & 0xFFFFFFFF
            if op == "shr":
                regs[dst_n] = (val >> cnt) & 0xFFFFFFFF
            elif op == "shl":
                regs[dst_n] = (val << cnt) & 0xFFFFFFFF
            else:  # sar
                if val & 0x80000000:
                    regs[dst_n] = ((val | ~0xFFFFFFFF) >> cnt) & 0xFFFFFFFF
                else:
                    regs[dst_n] = (val >> cnt) & 0xFFFFFFFF

        # ignore other ops (ret, etc.)
        else:
            continue

def test_move_chain(chain: list[Gadget], src: str, dst: str, preserve_regs: list[str] | None = None) -> bool:
    for r, v in SENTINELS.items():
        regs[r] = v
    stack.clear()
    memory.clear()

    for g in chain:
        emulate_gadget(g)

    if regs[dst] != SENTINELS[src]:
        return False

    if preserve_regs:
        for r in preserve_regs:
            if regs.get(r) != SENTINELS.get(r):
                return False

    return True

# ==============================================================================
#                               INTERACTIVE MENU
# ==============================================================================

def interactive_buckets_menu(buckets: dict[str, list[Gadget]],
                             gadgets: list[Gadget],
                             move_graph: dict[str, list[tuple[str, Gadget, list[str]]]]) -> None:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    BLUE    = "\033[34m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    CYAN    = "\033[36m"
    YELLOW  = "\033[33m"
    MAGENTA = "\033[35m"

    categories = list(buckets.keys())
    max_cat_len = max(len(cat) for cat in categories)
    count = len(categories)
    rows = (count + 2) // 3

    while True:
        # Header ASCII art
        print(f"{CYAN}{BOLD}")
        print("                                                            _")
        print("                                         ^^                /|\\")
        print("                   _____________________|  |_____         /||o\\")
        print(f"                  /________{RED}G A D G E T{CYAN} __________\\       /|o|||\\")
        print(f"                 /___________{RED}S H O P{CYAN} _____________\\     /|||||o|\\")
        print("                   ||___|___||||||||||||___|__|||      /||o||||||\\")
        print("                   ||___|___||||||||||||___|__|||          | |")
        print("                   ||||||||||||||||||||||||||||||oooooooooo| |ooooooo")
        print(f"    ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo{RESET}")

        # Print categories in 3 columns
        grid = []
        for r in range(rows):
            row_cells = []
            for c in range(3):
                idx = r + c * rows
                if idx < count:
                    num = idx + 1
                    cat = categories[idx]
                    cell = f"{YELLOW}{num}){RESET} {MAGENTA}{cat.ljust(max_cat_len)}{RESET}"
                    row_cells.append(cell)
                else:
                    row_cells.append(" " * (max_cat_len + 4))
            grid.append("\t\t".join(row_cells))

        for row in grid:
            print("    " + row)
        print()
        print(f"  {CYAN}S){RESET} Search instruction across all buckets")
        print(f"  {CYAN}A){RESET} Run AutoRop (save ESP → register)")
        print(f"  {CYAN}M){RESET} Run MoveGraph (Source → Dest)")
        print(f"  {RED}Type 'exit' to quit{RESET}\n")

        choice = input(f"{GREEN}Enter choice (number [REG - optional]/S/A/M/exit): {RESET}").strip().lower()
        if choice == "exit":
            print(f"{BOLD}Goodbye!{RESET}")
            break

        # Search mode
        if choice == "s":
            term = input(f"{GREEN}Enter instruction to search for: {RESET}").strip().lower()
            matches: list[tuple[Gadget, str]] = []
            for cat in categories:
                for g in buckets[cat]:
                    if any(term in instr for instr in g.instrs):
                        matches.append((g, cat))

            if not matches:
                print(f"{RED}No gadgets containing '{term}'.{RESET}")
            else:
                matches.sort(key=lambda x: len(x[0].instrs), reverse=True)
                print(f"\n{CYAN}{BOLD}Search results for '{term}':{RESET}")
                for g, cat in matches:
                    line = f"{BLUE}@ {g.address}{RESET} → "
                    for i, instr in enumerate(g.instrs):
                        il = instr.lower()
                        color = YELLOW if term in il else (RED if i % 2 == 0 else GREEN)
                        line += f"{color}{instr}{RESET}"
                        if i < len(g.instrs) - 1:
                            line += "; "
                    print(f"{MAGENTA}[{cat}]{RESET} {line}")
            continue

        # AutoRop mode
        if choice == "a":
            all_anchor_gadgets = auto_rop(gadgets)
            continue

        # MoveGraph mode
        if choice == "m":
            src = input("  Source register: ").strip().lower()
            dst = input("  Destination register: ").strip().lower()

            pr_input = input("  Preserve registers (e.g. eax,edi) [optional]: ").strip().lower()
            preserve = [r.strip() for r in re.split(r"[,\s]+", pr_input) if r.strip()] if pr_input else []
            if "esp" not in preserve:
                preserve.append("esp")

            invalid = [r for r in [src, dst] + preserve if r not in REGS_32]
            if invalid:
                print(f"{RED}[!] Invalid register name(s): {', '.join(invalid)}{RESET}")
                continue

            raw_paths = find_move_paths(move_graph, src, dst, max_depth=3, max_paths=100)
            valid_paths = []
            for path in raw_paths:
                chain = [step[2] for step in path]
                if test_move_chain(chain, src, dst, preserve):
                    valid_paths.append(path)

            if not valid_paths:
                print(f"{RED}[!] No valid move paths from {src.upper()} to {dst.upper()}.{RESET}")
            else:
                to_show = valid_paths[:20]
                for idx, path in enumerate(to_show, 1):
                    print(f"\n{CYAN}Path #{idx} ({len(path)} gadgets, preserves: {', '.join(preserve) or 'none'}):{RESET}")
                    for (_, _, g, _) in path:
                        print(f"  @ {g.address} → {g.text}")
                    # re-emulate to show final registers
                    for r, v in SENTINELS.items():
                        regs[r] = v
                    stack.clear()
                    memory.clear()
                    for (_, _, g, _) in path:
                        emulate_gadget(g)
                    state = ", ".join(f"{r.upper()}: {regs[r]:08X}" for r in REGS_32)
                    print(f"  {BOLD}Registers →{RESET} {state}")
                if len(valid_paths) > 20:
                    print(f"\n{YELLOW}…and {len(valid_paths) - 20} more paths not shown{RESET}")
            continue

        # Bucket selection
        parts = choice.split()
        if not parts[0].isdigit():
            print(f"{RED}[!] Invalid input. Enter number, 'S', 'A', 'M', or 'exit'.{RESET}")
            continue

        idx = int(parts[0])
        if not (1 <= idx <= len(categories)):
            print(f"{RED}[!] Choice out of range (1–{len(categories)}).{RESET}")
            continue

        reg_filter = parts[1].lower() if len(parts) > 1 else None
        if reg_filter:
            print(f"{YELLOW}Filtering for register: {reg_filter.upper()}{RESET}")

        cat_name = categories[idx - 1]
        lst = buckets[cat_name]
        filtered = [g for g in lst if not reg_filter or any(reg_filter in instr for instr in g.instrs)]

        print(f"\n{CYAN}{BOLD}{cat_name} gadgets{' (filtered)' if reg_filter else ''}:{RESET}")
        if not filtered:
            print(f"{RED}  No gadgets matching your criteria.{RESET}")
            continue

        for g in filtered:
            line = f"{BLUE}@ {g.address}{RESET} → "
            for i, instr in enumerate(g.instrs):
                il = instr.lower()
                if reg_filter and reg_filter in il:
                    color = YELLOW
                else:
                    color = RED if i % 2 == 0 else GREEN
                line += f"{color}{instr}{RESET}"
                if i < len(g.instrs) - 1:
                    line += "; "
            print("  " + line)

# ==============================================================================
#                               AUTOROP FUNCTIONALITY
# ==============================================================================

from typing import Callable
from struct import pack

def auto_rop(gadgets: list[Gadget]) -> tuple[
    bytes,            # rop_stage1:  4 bytes for the chosen anchor
    list[Gadget],     # suitable_anchors
    list[Gadget],     # store_candidates
    list[Gadget]      # load_candidates
]:
    """
    1) Gather three candidate lists:
         a) suitable_anchors: stack-anchor gadgets that preserve ESP and move its sentinel into another register.
         b) store_candidates: “MOV [REG], REG” store-to-memory gadgets that preserve ESP and whose base register has at least one INC/DEC/ADD/SUB.
         c) load_candidates: “MOV dst, [src + offset]” load-from-memory gadgets that preserve ESP and whose src register has a POP <src>.

    2) Immediately run Stage 1 “gate” by picking the single best anchor (fewest instructions),
       emulating it, and, on success, printing and returning its address as 4 bytes (little-endian).

    Returns:
      rop_stage1, suitable_anchors, store_candidates, load_candidates

    If no anchor passes Stage 1, rop_stage1 == b"" and an error message is printed.
    """

    global ADDR_VA_IAT_OFF, VA_IAT_ADJUST, BAD_BYTES

    # === Prompt for IAT offset and adjust to avoid bad bytes ===
    resp = input(f"Enter VirtualAlloc IAT offset in hex [default {ADDR_VA_IAT_OFF:#x}]: ").strip()
    if resp:
        try:
            ADDR_VA_IAT_OFF = int(resp, 16)
        except ValueError:
            print(f"Invalid hex: {resp}, using default {ADDR_VA_IAT_OFF:#x}", file=sys.stderr)
    print(f"[AutoRop] Using ADDR_VA_IAT_OFFSET = {ADDR_VA_IAT_OFF:#x}")

    orig = ADDR_VA_IAT_OFF
    new = orig
    adjust = 0
    while True:
        bstrs = chunk_address(f"0x{new:08x}")
        if not (set(bstrs) & BAD_BYTES):
            break
        adjust += 1
        new = orig + adjust

    if adjust:
        print(
            f"\033[31m[WARNING] IAT offset 0x{orig:08x} contains bad byte(s) "
            f"{set(bstrs)&BAD_BYTES}. bumping by 0x{adjust:x} → 0x{new:08x}\033[0m",
            file=sys.stderr
        )
        ADDR_VA_IAT_OFF = new
        VA_IAT_ADJUST = adjust
    else:
        VA_IAT_ADJUST = 0

    # ========================================================================
    # 1) Stack-anchor gadgets: preserve ESP & move its sentinel into another register
    # ========================================================================
    raw_anchors: list[tuple[Gadget, str]] = []
    for pattern_name, regex in [
        ("mov", PATTERNS["anchor_mov_esp"]),
        ("pushpop", PATTERNS["anchor_pushpop"])
    ]:
        for g in gadgets:
            instrs_str = "; ".join(g.instrs).lower()
            if regex.search(instrs_str):
                raw_anchors.append((g, pattern_name))

    suitable_anchors: list[Gadget] = []
    if raw_anchors:
        sentinel_esp = SENTINELS["esp"]
        for g, _ in raw_anchors:
            # Reset emulator state
            for r in REGS_32:
                regs[r] = SENTINELS[r]
            stack.clear()
            memory.clear()

            emulate_gadget(g)

            # ESP must still be sentinel, and some other register must hold that sentinel
            if regs["esp"] == sentinel_esp:
                for r in REGS_32:
                    if r != "esp" and regs[r] == sentinel_esp:
                        suitable_anchors.append(g)
                        break

    if not suitable_anchors:
        print("No suitable stack-anchor gadgets found or none passed emulation test.", file=sys.stderr)
    else:
        # Sort so fewest instructions appear first
        suitable_anchors.sort(key=lambda g: len(g.instrs))

        print(f"[AutoRop] Found {len(suitable_anchors)} suitable stack-anchor gadgets. Showing up to 10:\n")
        for idx, g in enumerate(suitable_anchors[:10], start=1):
            instrs_str = "; ".join(g.instrs)
            print(f"  #{idx} @ {g.address}  →  {instrs_str}")
        if len(suitable_anchors) > 10:
            print(f"  …and {len(suitable_anchors) - 10} more not shown.")

    # ========================================================================
    # 2) “MOV [REG], REG” store-to-memory gadgets that preserve ESP and have a base-reg modifier
    # ========================================================================
    store_candidates: list[Gadget] = []
    sentinel_esp = SENTINELS["esp"]

    deref_store_re = re.compile(
        rf"\bmov\s+(?:dword\s+)?\[\s*({'|'.join(REGS_32)})\s*\]\s*,\s*({'|'.join(REGS_32)})\b",
        re.IGNORECASE
    )

    regs_union = "|".join(REGS_32)
    inc_re_template = rf"\binc\s+{{reg}}\b"
    dec_re_template = rf"\bdec\s+{{reg}}\b"
    add_re_template = rf"\badd\s+{{reg}},\s*(?:{regs_union}|0x[0-9A-Fa-f]+)\b"
    sub_re_template = rf"\bsub\s+{{reg}},\s*(?:{regs_union}|0x[0-9A-Fa-f]+)\b"

    for g in gadgets:
        joined = "; ".join(g.instrs).lower()
        if not deref_store_re.search(joined):
            continue

        base_reg = None
        for instr in g.instrs:
            m_base = deref_store_re.search(instr)
            if m_base:
                base_reg = m_base.group(1).lower()
                break
        if base_reg is None:
            continue

        # Emulate to ensure ESP isn't clobbered
        for r in REGS_32:
            regs[r] = SENTINELS[r]
        stack.clear()
        memory.clear()
        emulate_gadget(g)
        if regs["esp"] != sentinel_esp:
            continue

        # Ensure INC, DEC, ADD, or SUB exists for base_reg
        inc_re = re.compile(inc_re_template.format(reg=base_reg), re.IGNORECASE)
        dec_re = re.compile(dec_re_template.format(reg=base_reg), re.IGNORECASE)
        add_re = re.compile(add_re_template.format(reg=base_reg), re.IGNORECASE)
        sub_re = re.compile(sub_re_template.format(reg=base_reg), re.IGNORECASE)

        found_modifier = False
        for g2 in gadgets:
            for instr2 in g2.instrs:
                il = instr2.lower()
                if inc_re.search(il) or dec_re.search(il) or add_re.search(il) or sub_re.search(il):
                    found_modifier = True
                    break
            if found_modifier:
                break

        if found_modifier:
            store_candidates.append(g)

    if not store_candidates:
        print(
            "\n[AutoRop] No “MOV [REG], REG” store-to-memory gadgets that "
            "satisfy ESP‐preserve and base‐reg modifier.",
            file=sys.stderr
        )
    else:
        # Sort so fewest instructions appear first
        store_candidates.sort(key=lambda g: len(g.instrs))

        print(f"\n[AutoRop] Found {len(store_candidates)} store-to-memory gadgets with valid modifiers. Showing up to 10:\n")
        for idx, g in enumerate(store_candidates[:10], start=1):
            instrs_str = "; ".join(g.instrs)
            print(f"  #{idx} @ {g.address}  →  {instrs_str}")
        if len(store_candidates) > 10:
            print(f"  …and {len(store_candidates) - 10} more not shown.")

    # ========================================================================
    # 3) “MOV dst, [src + optional offset]” load-from-memory gadgets that
    #    preserve ESP and whose source register has an available “pop <src>”
    # ========================================================================
    load_candidates: list[Gadget] = []
    sentinel_esp = SENTINELS["esp"]

    mov_reg_mem_re = re.compile(
        r'\bmov\s+('
        + '|'.join(REGS_ALL) +
        r')\s*,\s*(?:dword\s+)?\[\s*('
        + '|'.join(REGS_ALL) +
        r')(?:\s*[\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]',
        re.IGNORECASE
    )

    pop_re = re.compile(rf"\bpop\s+({'|'.join(REGS_ALL)})\b", re.IGNORECASE)
    pop_regs_available = set()
    for g in gadgets:
        for instr in g.instrs:
            m = pop_re.search(instr.lower())
            if m:
                pop_regs_available.add(m.group(1).lower())

    for g in gadgets:
        joined = "; ".join(g.instrs).lower()
        m_load = mov_reg_mem_re.search(joined)
        if not m_load:
            continue

        source_reg = m_load.group(2).lower()
        if source_reg not in pop_regs_available:
            continue

        # Emulate to ensure ESP isn't clobbered
        for r in REGS_32:
            regs[r] = SENTINELS[r]
        stack.clear()
        memory.clear()
        emulate_gadget(g)
        if regs["esp"] != sentinel_esp:
            continue

        load_candidates.append(g)

    if not load_candidates:
        print(
            "\n[AutoRop] No “MOV REG, [REG+...]” load-from-memory gadgets that "
            "preserve ESP and have a POP REG.",
            file=sys.stderr
        )
    else:
        # Sort so fewest instructions appear first
        load_candidates.sort(key=lambda g: len(g.instrs))

        print(
            f"\n[AutoRop] Found {len(load_candidates)} load-from-memory gadgets "
            "with valid POP modifiers. Showing up to 10:\n"
        )
        for idx, g in enumerate(load_candidates[:10], start=1):
            instrs_str = "; ".join(g.instrs)
            print(f"  #{idx} @ {g.address}  →  {instrs_str}")
        if len(load_candidates) > 10:
            print(f"  …and {len(load_candidates) - 10} more not shown.")

    # =============================================================================
    # Now: Stage 1 “gate” is run right here.  We have `suitable_anchors` (sorted fewest-first).
    # Pick the very first anchor that passes emulate_gadget → stage1_test().
    # =============================================================================
    rop_stage1 = b""
    if suitable_anchors:
        # The list was already sorted fewest-instr first, so just test index 0,1,2… until one passes
        last_index = -1
        sentinel_esp = SENTINELS["esp"]
        for idx in range(len(suitable_anchors)):
            g = suitable_anchors[idx]

            # Reset emulator
            for r in REGS_32:
                regs[r] = SENTINELS[r]
            stack.clear()
            memory.clear()

            emulate_gadget(g)
            # stage1_test checks “ESP still sentinel AND some other reg == sentinel”
            if stage1_test():
                rop_stage1 = pack("<L", int(g.address, 16))
                print(f"\n[AutoRop][Stage 1] Chose anchor @ {g.address}")
                break

        if not rop_stage1:
            print("\n[AutoRop][Stage 1] No anchor gadget passed the gate.", file=sys.stderr)
    else:
        print("\n[AutoRop][Stage 1] No suitable anchors to test.", file=sys.stderr)

    return rop_stage1, suitable_anchors, store_candidates, load_candidates


# ==============================================================================
#                         GENERIC STAGE-BUILDING HELPERS
# ==============================================================================

def stage1_test() -> bool:
    """
    After emulate_gadget(g), require:
      - regs['esp'] is still the sentinel
      - at least one other regs[r] == sentinel (ESP’s sentinel moved into another register)
    """
    sentinel_esp = SENTINELS["esp"]
    if regs["esp"] != sentinel_esp:
        return False
    for r in REGS_32:
        if r != "esp" and regs[r] == sentinel_esp:
            return True
    return False



# ==============================================================================
#                                  ARGUMENT PARSING
# ==============================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GadgetShop: filter RP++ gadgets and list useful ones"
    )
    p.add_argument(
        "-f", "--file", metavar="PATH", default="rop.txt",
        help="RP++ dump file to load (default: rop.txt)"
    )
    p.add_argument(
        "-b", "--bad-bytes", metavar="LIST",
        help=(
            "Quoted list of bad-byte tokens, comma- or space-separated. "
            "Formats: '\\x01, x02, 03, 0x04'"
        )
    )
    p.add_argument(
        "--filter-flow", action="store_true",
        help="Exclude any CALL or JMP gadgets"
    )
    p.add_argument(
        "--filter-c2", action="store_true",
        help="Exclude C2-style ‘retn 0xNN’ gadgets"
    )
    p.add_argument(
        "-o", "--output", required=True, metavar="OUTFILE",
        help="(MANDATORY) File to write filtered gadgets (stage1)"
    )
    p.add_argument(
        "--no-dedupe", "-nd", action="store_true",
        help="Skip deduplication of gadgets by instruction sequence"
    )
    return p.parse_args()

# ==============================================================================
#                                      MAIN
# ==============================================================================

def main() -> None:
    args = parse_args()
    path = Path(args.file)

    try:
        gadgets = load_gadgets(path)
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Loaded {len(gadgets)} gadgets from {args.file!r}", file=sys.stderr)

    if args.bad_bytes:
        toks = re.split(r"[,\s]+", args.bad_bytes.strip())
        before = len(gadgets)
        try:
            gadgets = filter_bad_bytes(gadgets, toks)
        except ValueError as e:
            print(f"[!] Error parsing bad-bytes: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Bad-byte filter removed {before - len(gadgets)} → {len(gadgets)} left", file=sys.stderr)
        BAD_BYTES.clear()
        for tok in toks:
            BAD_BYTES.add(normalize_bad_byte(tok))

    if args.filter_flow:
        before = len(gadgets)
        gadgets = filter_flow(gadgets)
        print(f"[+] CALL/JMP filter removed {before - len(gadgets)} → {len(gadgets)} left", file=sys.stderr)

    before = len(gadgets)
    gadgets = filter_leave(gadgets)
    print(f"[+] 'leave' filter removed {before - len(gadgets)} → {len(gadgets)} left", file=sys.stderr)

    before = len(gadgets)
    gadgets = filter_single_ret(gadgets)
    print(f"[+] Single-RET/RETN removed {before - len(gadgets)} → {len(gadgets)} left", file=sys.stderr)

    if args.filter_c2:
        before = len(gadgets)
        gadgets = filter_c2(gadgets)
        print(f"[+] C2-style filter removed {before - len(gadgets)} → {len(gadgets)} left", file=sys.stderr)

    dump_stage1(gadgets, Path(args.output))
    print(f"[+] Filtered gadgets written to {args.output!r}", file=sys.stderr)

    buckets    = find_useful(gadgets, dedupe=not args.no_dedupe)
    move_graph = build_move_graph(gadgets)
    interactive_buckets_menu(buckets, gadgets, move_graph)

if __name__ == "__main__":
    main()
