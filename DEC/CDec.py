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

import re
import os
import json
from capstone import *

class CapstoneDecompiler:
    def __init__(self, binary, base, complete):
        self.binary_data = binary
        self.base_address = base             
        self.architecture = "arm" if len(complete) >= 20 and complete[18] == 0xb7 else "x86"

        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if self.architecture == "arm" else Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True       
        self.reg_cleaner = {}
        try:
            folder = os.path.dirname(os.path.abspath(__file__))
            config = os.path.join(folder, "reg_map.json")
            with open(config, "r") as stream:
                data = json.load(stream)
            self.reg_cleaner = {key: val["clean_name"] for key, val in data["registers"].items()}
        except:           
            pass

    def clean_operand(self, op_str):        
        clean = op_str.replace("qword ptr", "").replace("dword ptr", "")
        clean = clean.replace("byte ptr", "").replace("word ptr", "").strip()                   
        clean = clean.replace("[", "").replace("]", "").strip()        

        matched = re.search(r'\b(rbp|rsp|sp|x29)\b\s*([-+,#])\s*(0x[0-9a-fA-F]+|[0-9]+)', clean)
        if matched:
            return f"local_var_{matched.group(3).replace('#', '')}h"            

        for reg, var in self.reg_cleaner.items():
            clean = re.sub(rf'\b{reg}\b', var, clean)
        return clean             

    def run_decompile(self):       
        active = False
        indent = "        "
        lines = []
        try:
            instructions = list(self.cs.disasm(self.binary_data, self.base_address))
        except:
            return "    // disassembly critical failure."
        if not instructions:
            return "    // No valid execution to decompile."

        loops = {int(ins.op_str.strip("#"), 16) if ins.op_str.strip("#").startswith("0x") else int(ins.op_str.strip("#")) for ins in instructions if (ins.mnemonic in ["jmp", "b"] or ins.mnemonic.startswith("j")) and (lambda t: t < ins.address)(int(ins.op_str.strip("#"), 16) if ins.op_str.strip("#").startswith("0x") else int(ins.op_str.strip("#")) if ins.op_str.strip("#").isdigit() else 0)}

        math_signs = {
            "add": "+=", "sub": "-=", "imul": "*=", "and": "&=", "or": "|=", "shl": "<<=", "shr": ">>=",
            "adds": "+=", "subs": "-=", "eor": "^=" 
        }
        comp_signs = {"je": "==", "jz": "==", "jne": "!=", "jnz": "!=", "jl": "<", "jg": ">", "cbz": "==", "cbnz": "!="}

        handlers = {
            "lea": lambda ops, ins, ind: f"{ind}{ops[0]} = &({ops[1]});",
            "mov": lambda ops, ins, ind: f"{ind}{ops[0]} = {ops[1]};" if len(ops) == 2 else f"{ind}{ops[0]} = {ops[1]};",
            "ldr": lambda ops, ins, ind: f"{ind}{ops[0]} = {ops[1]};" if len(ops) == 2 else f"{ind}{ops[0]} = {ops[1]};", # ARM64 Load
            "str": lambda ops, ins, ind: f"{ind}{ops[1]} = {ops[0]};" if len(ops) == 2 else f"{ind}{ops[1]} = {ops[0]};", # ARM64 Store
            "xor": lambda ops, ins, ind: f"{ind}{ops[0]} = 0;" if ops[0] == ops[1] else f"{ind}{ops[0]} ^= {ops[1]};",
            "call": lambda ops, ins, ind: f"{ind}sub_{ops[0]}();",
            "bl": lambda ops, ins, ind: f"{ind}sub_{ops[0]}();" # ARM64 Function Call
        }

        for index, insn in enumerate(instructions):                       
            if insn.address in loops:                
                lines.append(f"{indent}while (status_flag) {{ // Loop Recovery Triggered")
                indent += "    "

            mnemonic = insn.mnemonic

            if (mnemonic == "push" and "rbp" in insn.op_str) or (self.architecture == "arm" and index == 0):
                active = True
                lines.append(f"    // Function detected at {hex(insn.address)} ({'ARM64' if self.architecture == 'arm' else 'x86_64'})\n    void function_{hex(insn.address)}() {{")
                if self.architecture == "arm": continue

            if not active and index == 0:
                active = True                
                lines.append(f"    void entry_point_{hex(insn.address)}() {{")

            clean = self.clean_operand(insn.op_str)
            ops = [part.strip() for part in clean.split(",")] if "," in clean else [clean]

            if mnemonic in handlers and len(ops) >= 1:
                lines.append(handlers[mnemonic](ops, insn, indent))
            elif mnemonic in math_signs and len(ops) >= 2:
                lines.append(f"{indent}{ops[0]} {math_signs[mnemonic]} {ops[1]};")
            elif mnemonic.startswith("j") or mnemonic in ["jmp", "b", "bl", "br", "blr", "cbz", "cbnz"]:
                try:
                    target = int(insn.op_str, 16) if insn.op_str.startswith("0x") else int(insn.op_str)
                    if target < insn.address:
                        indent = indent[:-4] if len(indent) > 8 else "        "
                        lines.append(f"{indent}}} // End of While Loop")
                        continue
                except:
                    pass

                if mnemonic in ["jmp", "b"]:
                    lines.append(f"{indent}goto block_{clean};")
                elif mnemonic in ["cbz", "cbnz"] and len(ops) == 2:                  
                    lines.append(f"{indent}if ({ops[0]} {comp_signs[mnemonic]} 0) {{ goto block_{ops[1]}; }}")
                else:
                    condition = "status_flag"
                    if index > 0 and instructions[index - 1].mnemonic == "cmp":
                        prev_ops = [p.strip() for p in self.clean_operand(instructions[index - 1].op_str).split(",")]
                        if len(prev_ops) == 2:
                            condition = f"{prev_ops[0]} {comp_signs.get(mnemonic, '==')} {prev_ops[1]}"
                    lines.append(f"{indent}if ({condition}) {{ goto block_{clean}; }}")
            elif mnemonic in ["ret", "hlt"]:
                lines.append(f"{indent}return;\n    }}")
                active = False

        if active:
            lines.append(f"{indent}return;\n    }}")                   

        return "\n".join(lines) if lines else "    // disassembly block."
