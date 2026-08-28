#   Copyright 2026 Skokoo

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import os
import sys
import re
import json
from capstone import *

class Disasm:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):
        count = 15
        if args and isinstance(args, list) and len(args) > 0:
            try: count = int(args[0])
            except: pass

        cursor = self.shell.cursor
        binary = self.shell.binary_data            
        architecture = "aarch64" if len(binary) >= 20 and binary[18] == 0xb7 else "x86_64"     
        vaddr = self.shell.base_address + cursor

        bold, reset, white = self.shell.BOLD, self.shell.RESET, self.shell.WHITE
        red, magenta, yellow, green = self.shell.RED, self.shell.MAGENTA, self.shell.YELLOW, self.shell.GREEN

        if cursor < 0x40:
            return f"\n[\033[1mWARNING\033[0m] address {hex(vaddr)} is inside ELF header identity layout.\n"

        current_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(os.path.dirname(current_dir), "INFO", "reg_map.json")

        reg_map = {}
        if os.path.exists(json_path):
            try:
                with open(json_path, "r") as stream:
                    db = json.load(stream)
                    reg_map = db.get(architecture, {})
            except:
                pass

        if architecture == "aarch64":
            local_cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        else:
            local_cs = Cs(CS_ARCH_X86, CS_MODE_64)
        local_cs.detail = True

        chunk = binary[cursor : cursor + (count * 4 if architecture == "aarch64" else count * 15)]

        lines = [
            f"\n[\033[1mINFO\033[0m] Disassembly at {hex(vaddr)} ({'ARM64' if architecture == 'aarch64' else 'x86_64'})", 
            f"{bold}Address\t\tHex Bytes\t\tFlow\tInstruction{reset}", 
            "-" * 85
        ]
 
        pattern = r'\b(' + '|'.join(reg_map.keys()) + r')\b' if reg_map else (r'\b(x\d+|w\d+|sp|wsp|pc|lr|xzr|wzr)\b' if architecture == "aarch64" else r'\b(r[a-d]x|e[a-d]x|rsp|rbp|esp|ebp|rsi|rdi|r\d+)\b')

        index = 0
        for insn in local_cs.disasm(chunk, vaddr):
            if index >= count: 
                break

            bytes_str = "".join(f"{b:02x}" for b in insn.bytes).ljust(18)
            operands = insn.op_str

            if reg_map:
                for reg, meta in reg_map.items():
                    operands = re.sub(rf'\b{reg}\b', meta["clean_name"], operands)

            if reg_map:
                clean_names_pattern = r'\b(' + '|'.join(meta["clean_name"] for meta in reg_map.values()) + r')\b'
                operands = re.sub(clean_names_pattern, f"{bold}\\1{reset}", operands)
            else:
                operands = re.sub(pattern, f"{bold}\\1{reset}", operands)

            operands = re.sub(r'(0x[0-9a-fA-F]+)', f"{bold}\\1{reset}", operands)

            mnemonic = insn.mnemonic
            flow = f"{white}│{reset}"

            if mnemonic.startswith('j') or (architecture == "aarch64" and mnemonic in ['b', 'bl', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz']):
                mnemonic = f"{red}{bold}{mnemonic}{reset}"
                flow = f"{bold}├── [JMP]{reset}"
            elif mnemonic == 'call' or (architecture == "aarch64" and mnemonic == 'bl'):
                mnemonic = f"{magenta}{bold}{mnemonic}{reset}"
                flow = f"{magenta}├── [CALL]{reset}"
            elif mnemonic in ['ret', 'hlt']:
                mnemonic = f"{yellow}{bold}{mnemonic}{reset}"
                flow = f"{yellow}└── [END]{reset}"
            elif mnemonic in ['xor', 'sub', 'add', 'cmp', 'eor', 'subs', 'adds', 'and', 'ands', 'orr', 'eon']:
                mnemonic = f"{green}{mnemonic}{reset}"

            lines.append(f"  {white}{hex(insn.address)}{reset}\t{bytes_str}\t{flow}\t{mnemonic} {operands}")
            index += 1

        lines.append("-" * 85 + "\n")
        return "\n".join(lines)
