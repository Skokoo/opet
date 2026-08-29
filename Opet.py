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

import sys
import os
import re
import subprocess
import math
try:
    from capstone import *
except Exception:
    print("[\033[1mERROR\033[0m] Did you just forgot to install the package 'capstone'? please install it by execute following command: 'pip install capstone.'")
    sys.exit(1) 

current_dir = os.path.dirname(os.path.abspath(__file__))
dec_folder_path = os.path.join(current_dir, "DEC")

if dec_folder_path not in sys.path:
    sys.path.insert(0, dec_folder_path)
try:
    from CDec import CapstoneDecompiler
except ImportError:
    print(f"[\033[1mERROR\033[0m] the file 'CDec.py' not found in this directory: {dec_folder_path}")
    sys.exit(1)

info_folder_path = os.path.join(current_dir, "INFO")
if info_folder_path not in sys.path:
    sys.path.insert(0, info_folder_path)
try:
    from Info import InfoValidator
except ImportError:
    print(f"[\033[1mERROR\033[0m] the file 'Info.py' not found in this directory: {info_folder_path}")
    sys.exit(1)

func_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "FUNC")

if func_dir not in sys.path:
    sys.path.insert(0, func_dir)
try:
    from AI import run_ai
except ImportError:
    print(f"[\033[1mERROR\033[0m] the file 'AI.py' not found in this directory: {func_dir}")
    sys.exit(1)

modules = {}

if not os.path.exists(func_dir):
    print(f"[\033[1mERROR\033[0m] the directory 'FUNC' not found in path: {func_dir}")
else:
    import inspect
    import importlib           

    import_targets = [
        ("Disasm", "Disasm"),
        ("HexDump", "Hexdump"),
        ("Strings", "StringsExtract"),
        ("Analyze", "Analyze"),
        ("Seeker", "Seeker"),
        ("Integrity", "Integrity"),
        ("Shred", "Shred")
    ]            

    for file_name, class_name in import_targets:
        try:
            mod = importlib.import_module(f"FUNC.{file_name}")
            cls = getattr(mod, class_name)
            modules[class_name] = cls
        except Exception as e:
            print(f"[\033[1mERROR\033[0m] encountered some error: {file_name}.{class_name}: {e}")
            sys.exit(1)

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[34m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"

class Runnow:
    def __init__(self, filepath):
        self.filepath = filepath
        self.cursor = 0x0
        self.base_address = 0x10000000
        self.last_args = None
        self.modules = modules        
        self.GREEN = GREEN
        self.RED = RED
        self.CYAN = CYAN
        self.RESET = RESET
        self.MAGENTA = MAGENTA
        self.BOLD = BOLD
        self.WHITE = WHITE
        self.YELLOW = YELLOW
        self.BLUE = BLUE

        try:
            with open(filepath, "rb") as f:
                self.binary_data = bytearray(f.read())
            self.file_size = len(self.binary_data)
        except Exception as e:
            print(f"[\033[1mWARNING*\033[0m] encountered some error: \033[1m{e}\033[0m")
            sys.exit(1)

        if self.file_size > 4 and self.binary_data[4] != 2:
            print("[\033[1mERROR\033[0m] unsupported architecture. Architecture only support 64-bit only, for now.")
            sys.exit(1)

        self.arch_type = "x86_64"
        if len(self.binary_data) > 0x12:       
            if self.binary_data[0x12] == 0xb7:
                self.arch_type = "aarch64"

        if self.arch_type == "aarch64":
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM) 
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)    

        self.cs.detail = True               
        idx = self.binary_data.find(b"\x55\x48\x89\xE5")
        self.cursor = idx if idx != -1 else 0x0   

    def auto_detect_entry_point(self):
        idx = self.binary_data.find(b"\x55\x48\x89\xE5")
        self.cursor = idx if idx != -1 else (self.binary_data.find(b"\xFF\x43\x00\xD1") if self.binary_data.find(b"\xFF\x43\x00\xD1") != -1 else 0x0)

    def calculate_entropy(self, data):
        if not data: return 0
        length = len(data)               
        return -sum((count / length) * math.log2(count / length) for count in [data.count(byte) for byte in set(data)])

    def syntax_color(self, text):
        text = re.sub(r'(//.*)', r'\033[38;5;239m\1\033[0m', text)
        text = re.sub(r'\b(void|return|if|arg\d+|arg\d+_32|local_res)\b', r'\033[34m\1\033[0m', text)
        text = re.sub(r'\b(byte\s+ptr|dword\s+ptr)\b', r'\033[34m\1\033[0m', text)                    
        return text

    def check_and_print(self, out_str):
        if out_str is None or not isinstance(out_str, str):
            print("[\033[1mWARNING\033[0m] decompiler returned no or empty block.")
            return

        lines = out_str.split("\n")
        argument = " ".join(self.last_args) if hasattr(self, 'last_args') and self.last_args else ""

        cut_match = re.search(r'-cut\s+(\d+)', argument)
        lines = lines[:int(cut_match.group(1))] if cut_match else lines
        out_str = "\n".join(lines) if cut_match else out_str

        out_match = re.search(r'-o\s+(\S+)', argument)
        outfile = out_match.group(1) if out_match else None

        if outfile and os.path.exists(outfile):
            print(f"[\033[1mWARNING\033[0m] file '{outfile}' \033[1malready exists.\033[0m")
            choice = input("Overwrite? (y: do it / n: no / p: print it): ").strip().lower()
            outfile = None if choice == 'p' else (outfile if choice == 'y' else "CANCEL")
            if outfile == "CANCEL":
                print("[\033[1mINFO\033[0m] export canceled.")
                return

        if outfile:
            try:
                with open(outfile, "w", encoding="utf-8") as stream:
                    stream.write(re.sub(r'\033\[[0-9;]*m', '', out_str))
                print(f"[\033[1mINFO\033[0m] exported \033[1m{len(lines)}\033[0m lines to: {outfile}")
                return
            except Exception as failure:
                print(f"[\033[1mWARNING\033[0m] failed to write this file: \033[1m{failure}\033[0m")

        if len(out_str) > 1500 and input(f"print \033[1m{len(out_str)}\033[0m chars (\033[1m{len(lines)}\033[0m lines)? (y/n)").strip().lower() != 'y':
            print("[\033[1mWARNING\033[0m] printing canceled.")
            return            

        print(out_str)

    def translate_bytes_to_c(self, chunk, start_vaddr):
        c_lines = [f"    // auto decompile code block at {hex(start_vaddr)} ", "    {"]
        last_cmp = ""      

        is_aarch64 = hasattr(self, 'arch_type') and self.arch_type == "aarch64"
        reg_map = {"x0": "arg1", "x1": "arg2", "x2": "arg3", "x3": "arg4", "w0": "arg1_32"} if is_aarch64 else {"rdi": "arg1", "rsi": "arg2", "rdx": "arg3", "rcx": "arg4", "rax": "local_res"}

        def clean_op(val):
            val = val.strip()
            if val.startswith("[") and val.endswith("]"):
                return f"*(uint64_t*)({val[1:-1].strip()})"
            return val

        handlers = {
            "mov": lambda o, i: f"        {clean_op(o[0])} = {clean_op(o[1])};",
            "ldr": lambda o, i: f"        {clean_op(o[0])} = {clean_op(o[1])};",
            "str": lambda o, i: f"        {clean_op(o[1])} = {clean_op(o[0])};",
            "movz": lambda o, i: f"        {clean_op(o[0])} = {clean_op(o[1])};",
            "add": lambda o, i: f"        {clean_op(o[0])} = {clean_op(o[1])} + {clean_op(o[2])};" if len(o) > 2 else f"        {clean_op(o[0])} += {clean_op(o[1])};",
            "sub": lambda o, i: f"        {clean_op(o[0])} = {clean_op(o[1])} - {clean_op(o[2])};" if len(o) > 2 else f"        {clean_op(o[0])} -= {clean_op(o[1])};",
            "subs": lambda o, i: f"        {clean_op(o[0])} = {clean_op(o[1])} - {clean_op(o[2])};" if len(o) > 2 else f"        {clean_op(o[0])} -= {clean_op(o[1])};",
            "xor": lambda o, i: f"        {clean_op(o[0])} = 0;" if o[0].strip() == o[1].strip() else f"        {clean_op(o[0])} ^= {clean_op(o[1])};",
            "eor": lambda o, i: f"        {clean_op(o[0])} = 0;" if o[0].strip() == o[1].strip() else f"        {clean_op(o[0])} ^= {clean_op(o[1])};",
            "call": lambda o, i: f"        sub_{i.op_str.strip()}();",
            "bl": lambda o, i: f"        sub_{i.op_str.strip()}();",
            "blr": lambda o, i: f"        sub_{i.op_str.strip()}();",
        }                    

        for insn in self.cs.disasm(chunk, start_vaddr):
            op = insn.op_str
            for r, v in reg_map.items():
                op = re.sub(rf'\b{r}\b', v, op)          

            mnemonic = insn.mnemonic

            if "," in op:
                first_comma = op.find(",")
                dest = op[:first_comma].strip()
                rest = op[first_comma+1:].strip()

                if "[" in rest and "]" in rest:
                    parts = [dest, rest]
                else:
                    parts = [dest] + [p.strip() for p in rest.split(",")]
            else:
                parts = [op.strip()] if op else []

            current_line = ""

            if mnemonic in ["call", "bl", "blr"]:
                current_line = handlers[mnemonic](parts, insn)
            elif mnemonic in handlers and len(parts) >= 2:
                try:
                    current_line = handlers[mnemonic](parts, insn)
                except IndexError:
                    continue
            elif mnemonic in ["cmp", "subs"]: 
                last_cmp = op.replace(",", " == ")           
            elif mnemonic in ["je", "b.eq"] and last_cmp:
                current_line = f"        if ({last_cmp}) {{ // branch here"
            elif mnemonic in ["jne", "b.ne"] and last_cmp:
                current_line = f"        if (!({last_cmp})) {{ // branch here"            
            elif "ret" in mnemonic or mnemonic == "hlt":               
                c_lines.append(f"        return {'arg1' if is_aarch64 else 'local_res'};")
                break                         

            if current_line:
                is_padding_junk = False

                if is_aarch64:                   
                    if "xzr" in insn.op_str or "wzr" in insn.op_str or mnemonic in ["strb", "ldrb"] and "[x0]" in insn.op_str:
                        is_padding_junk = True
                else:                    
                    if "byte ptr" in current_line.lower() and "+=" in current_line:
                        is_padding_junk = True
                    elif any(x in current_line for x in ("+= al", "+= ch", "+= bl", "+= cl", "+= dl")):
                        is_padding_junk = True

                if is_padding_junk:
                    c_lines.append(f"{current_line}  \033[31m<-- null bytes here\033[0m")
                else:
                    c_lines.append(current_line)

        c_lines.append("    }")
        return "\n".join(c_lines)    

    def run_shell(self):
        filename = os.path.basename(self.filepath)
        print(f"[\033[1mINFO\033[0m] Loaded: \033[1m{filename}\033[0m ({self.file_size} bytes)")
        valid_cmds = ['pd', 'px', 'ax', 'ae', 'iz', 'asmd', 'info', 'ai', 'help', 'exit']      

        while True:
            try:
                archi = f"{CYAN}[AArch64]{RESET}" if self.arch_type == "aarch64" else f"{MAGENTA}[x86_64]{RESET}"
                prompt = f"{archi}_{BOLD}opet@{hex(self.cursor)}>{RESET} "
                raw_input = input(prompt).strip()
                if not raw_input: continue

                if raw_input.startswith("!"):
                    os.system(raw_input[1:])
                    continue

                cmd_input = raw_input.split()
                user_typed = cmd_input[0].lower()
                args = cmd_input[1:] if len(cmd_input) > 1 else None
                self.last_args = args                
                cmd = user_typed
                if user_typed not in valid_cmds:
                    matches = [c for c in valid_cmds if c.startswith(user_typed)]
                    if matches:
                        formatted_matches = ", ".join(f"'\033[1m{m}\033[0m'" for m in matches)
                        print(f"[\033[1mWARNING\033[0m] command not found. Did you mean: {formatted_matches}?")
                        continue                                          

                if cmd in ["q", "exit"]: 
                    break
                elif cmd in ["help", "?"]:  
                    help_text = (f"\n{BOLD}Available Commands:{RESET}\n"
                                 f"{BOLD}* Pipeline Flags{RESET}: most commands support parameters '-o <file>' for export and '-cut <lines>' for line slicing.\n\n"                                
                                 f"  {BOLD}pd{RESET} [lines]  : do stream 64 bit disassembly, no buffer freeze\n"
                                 f"  {BOLD}px{RESET} [bytes]  : display some raw byte hex dump and alignment layouts\n"
                                 f"  {BOLD}ax{RESET}          : looking for dynamic branch cross-references and relative RIP/PC vectors\n"
                                 f"  {BOLD}ae{RESET}          : packer detection using shannon entropy\n"
                                 f"  {BOLD}iz{RESET} [filter] : extract strings with some pseudo-C injection (Auto-Decompiler runtime)\n"
                                 f"  {BOLD}asmd{RESET} [size] : translate active block to some pseudo-C code\n"
                                 f"  {BOLD}shred{RESET}       : run global signature scanner\n"
                                 f"  {BOLD}s{RESET} <offset>  : seek address using log binary search with anti trap sugesstion\n"
                                 f"  {BOLD}info{RESET}        : scan file signatures and compiler metadata\n"
                                 f"  {BOLD}ai{RESET}          : validate section headers\n"
                                 f"  {BOLD}!{RESET}<command>  : pipe direct command execution routing to the native Linux shell\n"
                                 f"  {BOLD}?, help{RESET}     : show this guide\n"
                                 f"  q, {BOLD}exit{RESET}     : exit\n")                                                                                      
                    self.check_and_print(help_text)                 

                elif cmd == "pd":
                    if "Disasm" in self.modules:
                        self.check_and_print(self.modules["Disasm"](self).run(args))

                elif cmd == "px":
                    if "Hexdump" in self.modules:
                        self.check_and_print(self.modules["Hexdump"](self).run(args))

                elif cmd == "ai":
                    if "Integrity" in self.modules:
                        self.check_and_print(self.modules["Integrity"](self).run(args))

                elif cmd == "shred":
                    if "Shred" in self.modules:
                        self.check_and_print(self.modules["Shred"](self).run(args))

                elif cmd == "iz":
                    if "StringsExtract" in self.modules:                      
                        self.modules["StringsExtract"](self).run(args)

                elif cmd == "ax":
                    if "Analyze" in self.modules:
                        self.check_and_print(self.modules["Analyze"](self).runXREF(args))

                elif cmd == "ae":
                    if "Analyze" in self.modules:
                        self.check_and_print(self.modules["Analyze"](self).EntropyMap())

                elif cmd == "asmd":
                    chunk_size = 64
                    if args:
                        try:
                            chunk_size = int(args)
                        except:
                            pass
                    if self.cursor + chunk_size <= self.file_size:
                        code_chunk = self.binary_data[self.cursor : self.cursor + chunk_size]
                        vaddr_start = self.base_address + self.cursor
                        decompiler = CapstoneDecompiler(code_chunk, vaddr_start, self.binary_data)
                        pseudo_c = decompiler.run_decompile()

                        if pseudo_c is not None:
                            self.check_and_print(pseudo_c)
                        else:
                            print("[\033[1mERROR\033[0m] decompiler just returned empty data for you.")
                    else:
                        print("[\033[1mWARNING\033[0m] cursor position near EOF. And i must decompile it?")
                elif cmd == "info":                     
                    engine = InfoValidator(self.binary_data)
                    rep = engine.run_pipeline()
                    self.check_and_print(rep)
                elif cmd == "s" and args:
                    if "Seeker" in self.modules:
                        self.check_and_print(self.modules["Seeker"](self).run(args))

                else:
                    print("[\033[1mWARNING\033[0m] unknow command. Type \033[1m'help'\033[0m for options.")
            except (KeyboardInterrupt, EOFError):                
                break                                                                                                                        

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: \033[1mpython {sys.argv[0]} <binary_path>\033[0m")
        sys.exit(1)

    if "-ai" in sys.argv:
        sys.argv.remove("-ai") 
        run_ai(sys.argv[1])
    else:
        engine = Runnow(sys.argv[1])
        engine.run_shell()
