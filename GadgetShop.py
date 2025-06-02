#!/usr/bin/env python3
import re
import sys
import argparse
from pathlib import Path
import re
from struct import pack
from collections import deque

# list of registers we care about for “useful” patterns
REGS = ["eax","ebx","ecx","edx","esi","edi","esp","ebp","al","bl","cl","dl"]

# number of bytes from the ROP‐pivoted ESP back to the start of our VA skeleton
OFFSET_VA = 0x1C

# user‐supplied RVA of VirtualAlloc IAT entry (we’ll prompt for this in AutoRop)
ADDR_VA_IAT_OFFSET = 0x0

VA_IAT_ADJUST = 0x0
BAD_BYTES = set()

# a separate list of 32-bit registers for our emulator/tracking
TRACK_REGS = ["eax","ebx","ecx","edx","esi","edi","esp","ebp"]
LOW8_REG_MAP = {"al":"eax","bl":"ebx","cl":"ecx","dl":"edx"}
LOW16_REG_MAP = {"ax":"eax","bx":"ebx","cx":"ecx","dx":"edx","si":"esi","di":"edi","sp":"esp","bp":"ebp"}


# Pseudo‐register file for testing move chains
SENTINELS = {
    "eax": 0x11111111,
    "ebx": 0x22222222,
    "ecx": 0x33333333,
    "edx": 0x44444444,
    "esi": 0x55555555,
    "edi": 0x66666666,
    "esp": 0x57ACADD1,
    "ebp": 0x88888888,
}

# our pseudo-CPU state (only 32-bit regs here)
regs = { r: 0 for r in TRACK_REGS }
regs["esp"] = 0x57ACADD1
stack = []
memory = {}          # address -> 32-bit value
UNCONTROLLED = 0xDEADBEEF

# AutoRop - Step 1 - Get ESP saved
# these regexes will match anywhere in the instr string
# AutoRop step-1 patterns (module-scope)
# AutoRop - Step 1 - Get ESP saved (no longer accepting XCHG‐ESP gadgets)
ANCHOR_PATTERNS = [
    # pure MOV REG, ESP
    ("mov",  re.compile(r'\bmov\s+(' + '|'.join(REGS) + r'),\s*esp\b', re.IGNORECASE)),
    # pure PUSH ESP ; POP REG
    ("pushpop", re.compile(
        r'\bpush\s+esp\b(?:\s*;\s*[^;]+)*\s*;\s*pop\s+(' + '|'.join(REGS) + r')\b',
        re.IGNORECASE)),
    # <no more xchg patterns here>
]

# Regex to catch any instruction that writes to ESP
ESP_WRITE_RE = re.compile(
    r'\b(?:mov|lea)\s+esp\b|\bpop\s+esp\b',
    re.IGNORECASE
)


# compile once for performance
GADGET_LINE_RE = re.compile(r'^\s*0x[0-9A-Fa-f]{8}:')

def test_move_chain(chain, src, dst,preserve_regs=None):
    """
    Reset regs → run each gadget via emulate_gadget() → then
    return True if regs[dst] == SENTINELS[src], else False.
    """
    # 1) reset the global pseudo-regs & stack
    for r, v in SENTINELS.items():
        regs[r] = v
    stack.clear()

    # 2) execute the gadgets in sequence
    for g in chain:
        emulate_gadget(g)

    # 3) check if the destination got the source's sentinel
    if regs[dst] != SENTINELS[src]:
        return False
    
    # 4) ensure each preserved register still has its sentinel
    if preserve_regs:
        for r in preserve_regs:
            # if any preserved reg is clobbered, fail
            if regs.get(r, None) != SENTINELS.get(r, None):
                return False
    return True
    
def emulate_gadget(gadget):
    """
    Emulate a single ROP gadget's effects on regs, stack, and memory.
    If a memory load/store uses an unknown address, reads UNCONTROLLED.
    """
    for instr in gadget.instrs:
        parts = instr.strip().split(None,1)
        op = parts[0].lower()
        args = parts[1] if len(parts)>1 else ""
        # PUSH
        if op == "push":
            r = args.strip().lower()
            if r in regs:
                stack.append(regs[r])
        # POP
        elif op == "pop":
            r = args.strip().lower()
            if r in regs:
                regs[r] = stack.pop() if stack else 0
        # XCHG r, r2 or [r], r etc: handle register-register
        elif op == "xchg":
            a,b = [x.strip("[] ") for x in args.split(",",1)]
            if a in regs and b in regs:
                regs[a], regs[b] = regs[b], regs[a]
        # MOV variants
        elif op == "mov":
            dst, src = [x.strip() for x in args.split(",",1)]
            # memory store: mov [base+off], reg
            m = re.match(r'^\[\s*([^\+\-\]]+)\s*([\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]$', dst)
            if m and src.lower() in regs:
                base = m.group(1).lower()
                off = int(m.group(2).replace(" ",""),16) if m.group(2) else 0
                addr = regs.get(base,0) + off
                memory[addr] = regs[src.lower()]
            # memory load: mov reg, [base+off]
            elif re.match(r'^\[\s*', src):
                m2 = re.match(r'^\[\s*([^\+\-\]]+)\s*([\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]$', src)
                if dst.lower() in regs and m2:
                    base = m2.group(1).lower()
                    off = int(m2.group(2).replace(" ",""),16) if m2.group(2) else 0
                    addr = regs.get(base,0) + off
                    regs[dst.lower()] = memory.get(addr, UNCONTROLLED)
            # reg-to-reg or immediate
            else:
                # strip any size prefix
                if dst.lower() in regs:
                    val = None
                    if src.lower() in regs:
                        val = regs[src.lower()]
                    elif src.lower() in LOW8_REG_MAP:
                        val = regs[LOW8_REG_MAP[src.lower()]] & 0xff
                    elif src.lower() in LOW16_REG_MAP:
                        val = regs[LOW16_REG_MAP[src.lower()]] & 0xffff
                    else:
                        try:
                            val = int(src,16)
                        except:
                            val = None
                    if val is not None:
                        # handle 8-bit dest
                        if dst.lower() in LOW8_REG_MAP:
                            p = LOW8_REG_MAP[dst.lower()]
                            regs[p] = (regs[p] & ~0xff) | (val & 0xff)
                        # handle 16-bit dest
                        elif dst.lower() in LOW16_REG_MAP:
                            p = LOW16_REG_MAP[dst.lower()]
                            regs[p] = (regs[p] & ~0xffff) | (val & 0xffff)
                        else:
                            regs[dst.lower()] = val & 0xffffffff
        # LEA
        elif op == "lea":
            dst, mem = [x.strip() for x in args.split(",",1)]
            m = re.match(r'^\[\s*([^\+\-\]]+)\s*([\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]$', mem)
            if dst.lower() in regs and m:
                base = m.group(1).lower()
                off = int(m.group(2).replace(" ",""),16) if m.group(2) else 0
                addr = regs.get(base,0) + off
                regs[dst.lower()] = addr & 0xffffffff
        # Arithmetic: inc/dec/add/sub/neg
        elif op == "inc":
            r = args.strip().lower()
            if r in regs: regs[r] = (regs[r] + 1) & 0xffffffff
        elif op == "dec":
            r = args.strip().lower()
            if r in regs: regs[r] = (regs[r] - 1) & 0xffffffff
        elif op == "neg":
            r = args.strip().lower()
            if r in regs: regs[r] = (-regs[r]) & 0xffffffff
        elif op in ("add","sub","and","or","xor"):
            dst_src = args.split(",",1)
            if len(dst_src)!=2: continue
            dst = dst_src[0].strip().lower()
            src = dst_src[1].strip().lower()
            if dst not in regs and dst not in LOW8_REG_MAP and dst not in LOW16_REG_MAP:
                continue
            # get source value
            if src in regs:
                val = regs[src]
            elif src in LOW8_REG_MAP:
                val = regs[LOW8_REG_MAP[src]] & 0xff
            elif src in LOW16_REG_MAP:
                val = regs[LOW16_REG_MAP[src]] & 0xffff
            else:
                try: val = int(src,16)
                except: continue
            # apply
            opmap = {
                "add": lambda a,b: a+b,
                "sub": lambda a,b: a-b,
                "and": lambda a,b: a&b,
                "or":  lambda a,b: a|b,
                "xor": lambda a,b: a^b,
            }
            res = opmap[op](regs.get(dst,0), val)
            # commit with mask
            if dst in LOW8_REG_MAP:
                p = LOW8_REG_MAP[dst]; regs[p] = (regs[p]&~0xff)|(res&0xff)
            elif dst in LOW16_REG_MAP:
                p = LOW16_REG_MAP[dst]; regs[p] = (regs[p]&~0xffff)|(res&0xffff)
            else:
                regs[dst] = res & 0xffffffff
        # Shifts (logical)
        elif op in ("shr","shl","sar"):
            dst_n = args.split(",",1)[0].strip().lower()
            if dst_n not in regs: continue
            try:
                cnt = int(args.split(",",1)[1],16)
            except:
                continue
            val = regs[dst_n] & 0xffffffff
            if op=="shr":
                res = val >> cnt
            elif op=="shl":
                res = (val << cnt) & 0xffffffff
            else:  # sar
                # arithmetic shift
                if val & 0x80000000:
                    res = ((val | ~0xffffffff) >> cnt) & 0xffffffff
                else:
                    res = val >> cnt
            regs[dst_n] = res
        # ignore ret, other ops
        else:
            continue

def interactive_buckets_menu(buckets, gadgets, move_graph):
    import re

    # ANSI color/style codes
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    BLUE    = "\033[34m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    CYAN    = "\033[36m"
    YELLOW  = "\033[33m"
    MAGENTA = "\033[35m"

    categories = list(buckets.keys())

    # Determine cell width so each of 3 columns lines up
    CELL_W = max(len(f"{i+1}) {cat}") for i, cat in enumerate(categories)) + 2

    # Build a 3×n grid (shelf rows) from categories
    cols = 3
    rows = (len(categories) + cols - 1) // cols
    grid = []
    for r in range(rows):
        row_cells = []
        for c in range(cols):
            idx = r + c * rows
            if idx < len(categories):
                num = idx + 1
                cat = categories[idx]
                cell = f"{num}) {cat}".ljust(CELL_W)
                row_cells.append(cell)
            else:
                row_cells.append(" " * CELL_W)
        grid.append(row_cells)

    while True:
        # 1) ASCII Art Building Header
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

        # print categories in 3 columns, padded
        max_cat_len = max(len(cat) for cat in categories)
        count = len(categories)
        rows = (count + 2) // 3
        for r in range(rows):
            cols = []
            for c in range(3):
                idx = r + c * rows
                if idx < count:
                   num = idx + 1
                   cat = categories[idx]
                   cat_pad = cat.ljust(max_cat_len)
                   cols.append(f"{YELLOW}{num}){RESET} {MAGENTA}{cat_pad}{RESET}")
                else:
                   cols.append(" " * (max_cat_len + 4))
            print("    " + "\t\t".join(cols))
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
            matches = []
            for cat in categories:
                for g in buckets[cat]:
                    if any(term in instr.lower() for instr in g.instrs):
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
            auto_rop(gadgets)
            continue

        # MoveGraph mode
        if choice == "m":
            src = input("  Source register: ").strip().lower()
            dst = input("  Destination register: ").strip().lower()

            pr_input = input(
                "  Preserve registers (empty OR comma-separated, e.g. eax,edi): "
            ).strip().lower()
            if pr_input:
                preserve_regs = [r.strip() for r in re.split(r"[, \t]+", pr_input) if r.strip()]
            else:
                preserve_regs = []
            # always preserve ESP
            if "esp" not in preserve_regs:
                preserve_regs.append("esp")

            # validate
            bad = []
            for r in [src, dst] + preserve_regs:
                if r not in TRACK_REGS:
                    bad.append(r)
            if bad:
                print(f"{RED}[!] Invalid register name(s): {', '.join(bad)}{RESET}")
                continue

            raw_paths = find_move_paths(move_graph, src, dst, max_depth=3)
            valid_paths = []
            for path in raw_paths:
                gadget_chain = [step[2] for step in path]
                if test_move_chain(gadget_chain, src, dst, preserve_regs):
                    valid_paths.append(path)

            if not valid_paths:
                print(f"{RED}[!] No valid move paths from {src.upper()} to {dst.upper()}.{RESET}")
            else:
                to_show = valid_paths[:20]
                for idx, path in enumerate(to_show, 1):
                    print(f"\n{CYAN}Path #{idx} ({len(path)} gadgets, preserves: {', '.join(preserve_regs) or 'none'}):{RESET}")
                    for (_, _, g, _) in path:
                        print(f"  @ {g.address} → {g.text}")
                    # re-emulate to show final registers
                    for r, v in SENTINELS.items():
                        regs[r] = v
                    stack.clear()
                    memory.clear()
                    for (_, _, g, _) in path:
                        emulate_gadget(g)
                    state = ", ".join(f"{r.upper()}: {regs[r]:08X}" for r in TRACK_REGS)
                    print(f"  {BOLD}Registers →{RESET} {state}")
                if len(valid_paths) > 20:
                    print(f"\n{YELLOW}…and {len(valid_paths)-20} more paths not shown{RESET}")
            continue

        # Bucket display with optional register filter
        parts = choice.split()
        if not parts[0].isdigit():
            print(f"{RED}[!] Invalid input. Please enter a number, 'S', 'A', 'M', or 'exit'.{RESET}")
            continue
        n = int(parts[0])
        if not (1 <= n <= len(categories)):
            print(f"{RED}[!] Choice out of range (1–{len(categories)}).{RESET}")
            continue

        reg_filter = parts[1].lower() if len(parts) > 1 else None
        if reg_filter:
            print(f"{YELLOW}Filtering for register: {reg_filter.upper()}{RESET}")

        cat = categories[n - 1]
        lst = buckets[cat]
        filtered = [
            g for g in lst
            if not reg_filter or any(reg_filter in instr.lower() for instr in g.instrs)
        ]

        print(f"\n{CYAN}{BOLD}{cat} gadgets{' (filtered)' if reg_filter else ''}:{RESET}")
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


def auto_rop(gadgets):
    from struct import pack
    
    global ADDR_VA_IAT_OFFSET, VA_IAT_ADJUST, BAD_BYTES
    # prompt for the IAT offset
    resp = input(f"Enter VirtualAlloc IAT offset in hex [default {ADDR_VA_IAT_OFFSET:#x}]: ").strip()
    if resp:
        try:
            ADDR_VA_IAT_OFFSET = int(resp, 16)
        except ValueError:
            print(f"Invalid hex: {resp}, using default {ADDR_VA_IAT_OFFSET:#x}", file=sys.stderr)
    print(f"[AutoRop] Using ADDR_VA_IAT_OFFSET = {ADDR_VA_IAT_OFFSET:#x}")
    
    # if any byte in the 32-bit LE representation is “bad”, bump until clean
    orig = ADDR_VA_IAT_OFFSET
    new = orig
    adjust = 0
    while True:
        # split into two‐digit bytes
        bstrs = chunk_address(f"0x{new:08x}")
        if not (set(bstrs) & BAD_BYTES):
            break
        adjust += 1
        new = orig + adjust
    if adjust:
        from sys import stderr
        print(f"\033[31m[WARNING] IAT offset 0x{orig:08x} contains bad byte(s) {set(bstrs)&BAD_BYTES}.", file=stderr)
        print(f"[WARNING] bumping by 0x{adjust:x} → 0x{new:08x}\033[0m", file=stderr)
        ADDR_VA_IAT_OFFSET = new
        VA_IAT_ADJUST = adjust
    else:
        VA_IAT_ADJUST = 0
    
    # 1) Gather all matches
    candidates = []
    for name, pattern, core_regexes in ANCHOR_PATTERNS:
        for g in gadgets:
            instrs_str = "; ".join(g.instrs)
            if pattern.search(instrs_str.lower()):
                candidates.append((g, name, core_regexes))

    # 2) Pick the gadget with the smallest instruction count
    if not candidates:
        print("No suitable stack-anchor gadget found", file=sys.stderr)
        return None, []

    best_g, best_name, best_cores = min(candidates, key=lambda t: len(t[0].instrs))

    # 3) Extract core vs side‐effects
    core = []
    for instr in best_g.instrs:
        for cr in best_cores:
            if cr.match(instr):
                core.append(instr)
                break

    side = [i for i in best_g.instrs if i not in core and not i.lower().startswith("ret")]

    addr = int(best_g.address, 16)
    eip_pack = f'pack("<L", (0x{addr:08x}))'
    instrs_str = "; ".join(best_g.instrs)

    # 1) - Stack Anchor
    print("STACK ANCHOR:")
    print(f"Suitable Instruction Found: {best_g.address} → {instrs_str}")
    print(f"Side Effects: {'; '.join(side) or 'None'}")
    print(f"eip = {eip_pack}  # {instrs_str}")
    emulate_gadget(best_g)
    state = ", ".join(f"{r.upper()}: {regs[r]:08X}" for r in TRACK_REGS)
    print(f"R → {state}")
    print("==============================================================\n")

    return eip_pack, side

def detect_encoding(path):
    # read BOM to guess utf-16 vs latin-1
    with open(path, "rb") as f:
        bom = f.read(2)
    if bom in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    return "latin-1"

def chunk_address(addr):
    """Split '0xAABBCCDD' → ['aa','bb','cc','dd']"""
    h = addr[2:].lower()
    return [h[i:i+2] for i in range(0, len(h), 2)]

def normalize_bad_byte(tok):
    """Turn '\\x0a', '0x0a', 'x0a', '0a', 'a' → '0a'"""
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

class Gadget:
    __slots__ = ("address","instrs","text")
    def __init__(self, line):
        self.text = line.rstrip()
        addr, rest = line.split(":", 1)
        self.address = addr.strip()
        rest = re.sub(r'\(\d+\s+found\)\s*$', '', rest)
        self.instrs = [i.strip().lower() for i in rest.split(";") if i.strip()]

def load_gadgets(path):
    enc = detect_encoding(path)
    with open(path, encoding=enc, errors="ignore") as f:
        lines = [L for L in f if GADGET_LINE_RE.match(L)]
    return [Gadget(L) for L in lines]

def filter_bad_bytes(gadgets, bad_list):
    bad = { normalize_bad_byte(x) for x in bad_list }
    return [g for g in gadgets if not any(ch in bad for ch in chunk_address(g.address))]

def filter_flow(gadgets):
    def is_flow(instr):
        op = instr.split()[0]
        return op == "call" or op.startswith("jmp")
    return [g for g in gadgets if not any(is_flow(i) for i in g.instrs)]

def filter_single_ret(gadgets):
    """
    Remove any gadget composed of exactly one instruction,
    where that instruction is either:
      - 'ret'
      - 'retn 0xNN...' (a C2‐style return with immediate)
    """
    retn_immediate = re.compile(r'^retn(?:\s+0x[0-9a-f]+)?$')
    out = []
    for g in gadgets:
        if len(g.instrs) == 1 and (g.instrs[0] == "ret" or retn_immediate.match(g.instrs[0])):
            continue
        out.append(g)
    return out

def filter_c2(gadgets):
    def is_c2(i):
        return bool(re.match(r'^retn\s+0x[0-9a-f]+$', i))
    return [g for g in gadgets if not any(is_c2(i) for i in g.instrs)]

def filter_leave(gadgets):
    """
    Remove any gadget containing a 'leave' instruction.
    """
    return [
        g for g in gadgets
        if not any(instr.split()[0] == "leave" for instr in g.instrs)
    ]

def find_move_path(graph, src, dst):
    """
    Returns a list of (reg, gadget) pairs that walk src→dst,
    or None if no path exists.
    """
    q = deque([(src, [])])
    seen = {src}
    while q:
        reg, path = q.popleft()
        if reg == dst:
            return path
        for (nxt, gadget) in graph.get(reg, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            q.append((nxt, path + [(nxt, gadget)]))
    return None

def find_stack_address_gadget(all_gadgets):
    """
    Returns (gadget, side_effects) or (None, []).
    Chooses the first pattern in ANCHOR_PATTERNS that matches,
    then returns that Gadget and any extra instructions it carries.
    """
    for name, regex in ANCHOR_PATTERNS:
        for g in all_gadgets:
            instrs = "; ".join(g.instrs).lower()
            if regex.search(instrs):
                # figure out which instrs are the core ones
                core = []
                for instr in g.instrs:
                    if regex.match(instr):
                        core.append(instr)
                # everything else except the final ret is a side-effect
                side_effects = [
                    i for i in g.instrs
                    if i not in core and not i.lower().startswith("ret")
                ]
                return g, side_effects
    return None, []

def dump_stage1(gadgets, fname):
    with open(fname, "w") as o:
        for g in sorted(gadgets, key=lambda g: len(g.instrs)):
            o.write(g.text + "\n")

def find_useful(gadgets, dedupe=True):
    buckets = {
        "STACK ANCHOR": [],
        "STACK PIVOT": [],
        "POP REG": [],
        "PUSH REG/POP REG": [],
        "INC REG": [],
        "DEC REG": [],
        "NEG REG": [],
        "ADD REG,REG": [],
        "ADD REG,IMM": [],
        "SUB REG,REG": [],
        "SUB REG,IMM": [],
        "MOV REG,REG": [],        
        "MOV [REG],REG": [],
        "MOV REG,[REG]": [],
        "LEA REG,MEM":[],
        "XCHG REG,REG": [],
        "XCHG MEM,REG": [],
        "XOR REG,REG": []
    }
    
    pop_re     = re.compile(r'\bpop\s+(' + '|'.join(REGS) + r')\b')
    pop_re             = re.compile(r'\bpop\s+('        + '|'.join(REGS) + r')\b')
    pushpop_re         = re.compile(r'\bpush\s+('       + '|'.join(REGS) + r')\b(?:\s*;\s*[^;]+)*\s*;\s*pop\s+(' + '|'.join(REGS) + r')\b')
    inc_re             = re.compile(r'\binc\s+('        + '|'.join(REGS) + r')\b')
    dec_re             = re.compile(r'\bdec\s+('        + '|'.join(REGS) + r')\b')
    neg_re             = re.compile(r'\bneg\s+('        + '|'.join(REGS) + r')\b')
    add_rr             = re.compile(r'\badd\s+('        + '|'.join(REGS) + r'),\s*('    + '|'.join(REGS) + r')\b')
    add_ri             = re.compile(r'\badd\s+('        + '|'.join(REGS) + r'),\s*0x[0-9A-Fa-f]+\b')
    sub_rr             = re.compile(r'\bsub\s+('        + '|'.join(REGS) + r'),\s*('    + '|'.join(REGS) + r')\b')
    sub_ri             = re.compile(r'\bsub\s+('        + '|'.join(REGS) + r'),\s*0x[0-9A-Fa-f]+\b')
    xor_rr             = re.compile(r'\bxor\s+('        + '|'.join(REGS) + r'),\s*\1\b')
    mov_rr             = re.compile(r'\bmov\s+('        + '|'.join(REGS) + r'),\s*('    + '|'.join(REGS) + r')\b')
    xchg_rr            = re.compile(r'\bxchg\s+('       + '|'.join(REGS) + r'),\s*('    + '|'.join(REGS) + r')\b')
    deref_re           = re.compile(r'\bmov\s+(?:dword\s+)?\[\s*.*?\s*\],\s*(' + '|'.join(REGS) + r')\b', re.IGNORECASE)
    mov_reg_mem_re = re.compile(r'\bmov\s+(' + '|'.join(REGS) + r')\s*,\s*'r'(?:dword\s+)?' +r'\[\s*(' + '|'.join(REGS) + r')(?:\s*[\+\-]\s*0x[0-9A-Fa-f]+)?\s*\]',re.IGNORECASE)
    push_esp_re        = re.compile(r'\bpush\s+esp\b(?:\s*;\s*[^;]+)*\s*;\s*pop\s+(' + '|'.join(REGS) + r')\b')
    mov_reg_esp        = re.compile(r'\bmov\s+('        + '|'.join(REGS) + r'),\s*esp\b')
    lea_re             = re.compile(r'\blea\s+(' + '|'.join(REGS) + r')\s*,\s*(?:dword\s+)?\[\s*.*?\s*\]',re.IGNORECASE)
    xchg_reg_esp       = re.compile(r'\bxchg\s+('       + '|'.join(REGS) + r'),\s*esp\b|\bxchg\s+esp,\s*(' + '|'.join(REGS) + r')\b')
    lea_reg_esp        = re.compile(r'\blea\s+('        + '|'.join(REGS) + r'),\s*\[esp\]\b')
    mov_mem_esp        = re.compile(r'\bmov\s+\[('       + '|'.join(REGS) + r')\],\s*esp\b')
    mov_reg_memesp     = re.compile(r'\bmov\s+('        + '|'.join(REGS) + r'),\s*\[esp\]\b')
    pivot_re           = re.compile(r'\bxchg\s+esp\s*,\s*(' + '|'.join(REGS) + r')\b|\bxchg\s+(' + '|'.join(REGS) + r')\s*,\s*esp\b')
    xchg_mem_reg_re    = re.compile(r'\bxchg\s+\[('      + '|'.join(REGS) + r')\]\s*,\s*(' + '|'.join(REGS) + r')\b')
    xchg_reg_mem_re    = re.compile(r'\bxchg\s+('         + '|'.join(REGS) + r')\s*,\s*\[(' + '|'.join(REGS) + r')\]\b')

    for g in gadgets:
        instrs = "; ".join(g.instrs)
        tail   = "; ".join(g.instrs[:-1])
        if pop_re.search(instrs):
            buckets["POP REG"].append(g)
        if xor_rr.search(instrs):
            buckets["XOR REG,REG"].append(g)            
        if pushpop_re.search(instrs):
            buckets["PUSH REG/POP REG"].append(g)
        if xchg_mem_reg_re.search(instrs) or xchg_reg_mem_re.search(instrs):
            buckets["XCHG MEM,REG"].append(g)            
        if inc_re.search(instrs):
            buckets["INC REG"].append(g)
        if dec_re.search(instrs):
            buckets["DEC REG"].append(g)
        if add_rr.search(instrs):
            buckets["ADD REG,REG"].append(g)
        if add_ri.search(instrs):
            buckets["ADD REG,IMM"].append(g)
        if sub_rr.search(instrs):
            buckets["SUB REG,REG"].append(g)
        if sub_ri.search(instrs):
            buckets["SUB REG,IMM"].append(g)
        if mov_rr.search(instrs):
            buckets["MOV REG,REG"].append(g)
        if xchg_rr.search(instrs):
            buckets["XCHG REG,REG"].append(g)
        if deref_re.search(instrs):
            buckets["MOV [REG],REG"].append(g)
        if neg_re.search(instrs):
            buckets["NEG REG"].append(g)
        if ( push_esp_re.search(instrs)
          or mov_reg_esp.search(instrs)
          or lea_reg_esp.search(instrs)
          or mov_mem_esp.search(instrs)
          or mov_reg_memesp.search(instrs) ):
            buckets["STACK ANCHOR"].append(g)  
        if pivot_re.search(instrs):
            buckets["STACK PIVOT"].append(g)  
        if lea_re.search(instrs):
            buckets["LEA REG,MEM"].append(g)   
        if mov_reg_mem_re.search(instrs):
            buckets["MOV REG,[REG]"].append(g)

    # only run dedupe‐by‐instruction if requested
    if dedupe:
        for k in buckets:
            seen = set()
            unique = []
            for g in buckets[k]:
                instr_seq = re.sub(r';\s*retn?.*$', '', g.text, flags=re.IGNORECASE) \
                             .split(":", 1)[1].strip()
                if instr_seq not in seen:
                    seen.add(instr_seq)
                    unique.append(g)
            buckets[k] = unique
    
    # now sort each bucket: fewest instructions first
    for k in buckets:
        buckets[k].sort(key=lambda g: len(g.instrs), reverse=True)
    return buckets

def parse_args():
    p = argparse.ArgumentParser(
        description="GadgetShop: filter RP++ gadgets into stage1 and list useful ones"
    )
    p.add_argument(
        "-f", "--file",
        metavar="PATH",
        default="rop.txt",
        help="RP++ dump file to load (default: rop.txt)"
    )
    p.add_argument(
        "-b", "--bad-bytes",
        help=(
            "Quoted list of bad-byte tokens, comma- or space-separated. "
            "Accepted formats: '0x01, x02, \\x03, 04'"
        )
    )
    p.add_argument(
        "--filter-flow",
        action="store_true",
        help="Exclude any CALL or JMP gadgets"
    )
    p.add_argument(
        "--filter-c2",
        action="store_true",
        help="Exclude C2-style ‘retn 0xNN’ gadgets"
    )
    p.add_argument(
        "-o", "--output",
        required=True,
        metavar="OUTFILE",
        help="(MANDATORY) File to write filtered gadgets (stage1)"
    )
    p.add_argument(
        "--no-dedupe", "-nd",
        action="store_true",
        help="Skip deduplication of gadgets by instruction sequence"
    )
    return p.parse_args()

def build_move_graph(gadgets):
    import re

    regs = ["eax","ebx","ecx","edx","esi","edi","esp","ebp"]
    graph = { r: [] for r in regs }

    # regexes to detect moves and extract dst,src
    patterns = []
    patterns.append((
        re.compile(r'\bmov\s+('+'|'.join(regs)+r'),\s*('+'|'.join(regs)+r')\b', re.IGNORECASE),
        lambda m: (m.group(2).lower(), m.group(1).lower())
    ))
    patterns.append((
        re.compile(r'\bxchg\s+('+'|'.join(regs)+r')\s*,\s*('+'|'.join(regs)+r')\b', re.IGNORECASE),
        lambda m: ((m.group(2).lower(), m.group(1).lower()),
                   (m.group(1).lower(), m.group(2).lower()))
    ))
    patterns.append((
        re.compile(r'\bpush\s+('+'|'.join(regs)+r')\b(?:\s*;\s*[^;]+)*;\s*pop\s+('+'|'.join(regs)+r')\b', re.IGNORECASE),
        lambda m: (m.group(1).lower(), m.group(2).lower())
    ))
    patterns.append((
        re.compile(r'\blea\s+('+'|'.join(regs)+r')\s*,\s*\[\s*('+'|'.join(regs)+r')', re.IGNORECASE),
        lambda m: (m.group(2).lower(), m.group(1).lower())
    ))

    for g in gadgets:
        instrs_joined = "; ".join(g.instrs).lower()
        
        # Skip any gadget that writes to ESP
        if ESP_WRITE_RE.search(instrs_joined):
            continue
        # figure out which regs this gadget writes/clobbers
        dest_regs = set()
        for instr in g.instrs:
            op = instr.strip().split()[0]
            if op in ("mov","lea","xchg"):
                # first token pre-colon form: "mov dword [ecx], eax"
                # mov writes to the LHS: extract inside regex
                pass
        # simpler: any register that appears as a dest in instrs
        for instr in g.instrs:
            m = re.match(r'\b(pop|mov|xchg|lea)\b', instr)
            if not m: continue
            # split into dst,src
            parts = instr.replace(",", " ").split()
            # naive: dst is parts[1] if mov/xchg/lea, pop writes to parts[1]
            # collect only reg-names
            if m.group(1) == "pop":
                dst = parts[1]
                if dst in regs: dest_regs.add(dst)
            elif m.group(1) in ("mov","lea"):
                dst = parts[1].strip("[],")
                if dst in regs: dest_regs.add(dst)
            elif m.group(1) == "xchg":
                a,b = parts[1].strip(","), parts[2]
                if a in regs: dest_regs.add(a)
                if b in regs: dest_regs.add(b)

        for regex, extractor in patterns:
            match = regex.search("; ".join(g.instrs))
            if not match: 
                continue

            out = extractor(match)
            if isinstance(out[0], tuple):
                # xchg gave us two pairs
                pairs = out
            else:
                pairs = [out]

            for src, dst in pairs:
                # the gadget moves from src → dst
                # side-effects = all other dest_regs minus this dst
                side = list(dest_regs - {dst})
                graph[src].append((dst, g, side))

    return graph

def find_move_paths(graph, src, dst, max_depth=3):
    """
    Find *all* simple paths from src→dst up to max_depth gadgets.
    Returns a list of paths, where each path is a list of
    (src_reg, dst_reg, gadget, side_effects) tuples.
    """
    paths = []
    # queue entries are (current_register, path_so_far, visited_regs)
    q = deque([(src, [], {src})])

    while q:
        reg, path, seen = q.popleft()

        # if we’ve already used max_depth gadgets, don’t extend further
        if len(path) >= max_depth:
            # if we landed on dst exactly at depth, record it
            if reg == dst:
                paths.append(path)
            continue

        # otherwise extend one more gadget
        for (nxt, gadget, side) in graph.get(reg, []):
            if nxt in seen:
                continue
            new_path = path + [(reg, nxt, gadget, side)]
            if nxt == dst:
                paths.append(new_path)
            # enqueue for further exploration
            q.append((nxt, new_path, seen | {nxt}))

    # sort: fewest gadgets first, then *most* side-effects first
    paths.sort(key=lambda p: (len(p), -sum(len(step[3]) for step in p)))
    return paths

def main():
    args = parse_args()

    try:
        gadgets = load_gadgets(args.file)
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
        print(f"[+] Bad-byte filter removed {before-len(gadgets)} → {len(gadgets)} left", file=sys.stderr)
        # stash normalized bad-byte tokens for AutoRop
        BAD_BYTES.clear()
        for tok in toks:
            BAD_BYTES.add(normalize_bad_byte(tok))

    if args.filter_flow:
        before = len(gadgets)
        gadgets = filter_flow(gadgets)
        print(f"[+] CALL/JMP filter removed {before-len(gadgets)} → {len(gadgets)} left", file=sys.stderr)

    # always strip any gadgets that include a 'leave'
    before = len(gadgets)
    gadgets = filter_leave(gadgets)
    print(f"[+] 'leave' filter removed {before-len(gadgets)} → {len(gadgets)} left", file=sys.stderr)

    before = len(gadgets)
    gadgets = filter_single_ret(gadgets)
    print(f"[+] Single-RET/RETN removed {before-len(gadgets)} → {len(gadgets)} left", file=sys.stderr)

    if args.filter_c2:
        before = len(gadgets)
        gadgets = filter_c2(gadgets)
        print(f"[+] C2-style filter removed {before-len(gadgets)} → {len(gadgets)} left", file=sys.stderr)

    dump_stage1(gadgets, args.output)
    print(f"[+] Filtered gadgets written to {args.output!r}", file=sys.stderr)

        # 7) find useful gadgets and launch the menu
    buckets = find_useful(gadgets, dedupe=not args.no_dedupe)
    move_graph = build_move_graph(gadgets)
    interactive_buckets_menu(buckets, gadgets, move_graph)


if __name__ == "__main__":
    main()
