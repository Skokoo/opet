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

class StringsExtract:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):
        keyword = None
        if args and isinstance(args, list) and len(args) > 0:
            argument = str(args[0]).strip()           
            if not argument.startswith("-"):
                keyword = argument.lower()

        green = self.shell.GREEN
        red = self.shell.RED
        cyan = self.shell.CYAN
        reset = self.shell.RESET
        bold = self.shell.BOLD

        choice = input("Bypass Data Sanitization? (y: As-is Output / n: Filter Junk code): ").strip().lower()       

        is_aarch64 = hasattr(self.shell, 'arch_type') and self.shell.arch_type == "aarch64"

        signals = []
        x86_junk_regs = []
        if choice != 'y':
            signals = ["fs:", "gs:", "ss:"]
            x86_junk_regs = ["ch", "dh", "bh", "ah", "al", "bl", "cl", "dl"]

        print(f"[\033[1mINFO\033[0m] " + ("Sensor Disabled. Output raw emulation bytes." if choice == 'y' else "Sensor Enabled. Fidelity code filter active. \033[1mPlease note that this potentially lead to No Decompiling.\033[0m"))

        lines = [f"\n[\033[1mINFO\033[0m] Extracting Static Strings & Decompiling Associated Code..."]      

        matches = re.finditer(b"[\x20-\x7E]{5,}", self.shell.binary_data)
        sections = (".fini_array", ".init_array", ".text", ".data", ".rodata", 
                    ".comment", ".note", ".got", ".rela", ".dynstr", ".dynsym", 
                    ".eh_frame", ".gnu", ".symtab", ".strtab", ".shstrtab")

        for match in matches:
            text = match.group().decode('ascii', errors='ignore')         

            if text.startswith(".") or any(text.startswith(sec) for sec in sections) or len(set(text)) <= 1:
                continue

            if len(text) > 0 and (sum(1 for char in text if char.isalpha()) / len(text)) < 0.40:               
                continue

            if keyword and keyword not in text.lower(): 
                continue

            offset = match.start()
            vaddr = self.shell.base_address + offset                      
            color = red if any(x in text.lower() for x in ("http", ".exe", "select", "cmd", "password", "flag{")) else (cyan if any(x in text.lower() for x in ("debug", "assert", "gcc", "main")) else green)

            cursor = offset + len(match.group())
            if hasattr(self.shell, 'arch_type') and self.shell.arch_type == "aarch64":
                remainder = cursor % 4
                if remainder != 0:
                   cursor += (4 - remainder)

            if is_aarch64:
                remainder = cursor % 4
                if remainder != 0:
                    cursor += (4 - remainder)

            decompiled = ""

            if cursor + 64 <= self.shell.file_size:
                chunk = self.shell.binary_data[cursor : cursor + 64]
                current_vaddr = self.shell.base_address + cursor
                pseudo = self.shell.translate_bytes_to_c(chunk, current_vaddr)

                if pseudo and "{" in pseudo:
                    is_junk = False
                    if choice != 'y':
                        if any(sig in pseudo.lower() for sig in signals):
                            is_junk = True
                        elif not is_aarch64 and any(re.search(rf'\b{reg}\b', pseudo.lower()) for reg in x86_junk_regs):
                            is_junk = True

                    if not is_junk:
                        decompiled = pseudo

            lines.append(f"  {hex(offset)}\t{hex(vaddr)}\t-> \033[38;5;208m{text}{reset}")
            if decompiled and "{" in decompiled:
                if len(decompiled.strip().split("\n")) > 2:
                   colored = self.shell.syntax_color(decompiled)
                   lines.append(colored)               

        lines.append("")
        self.shell.check_and_print("\n".join(lines))

        if choice == 'y':
            print(f"\n{bold}[TIPS]{reset}\n[i] don't forget to check the output, \033[1mdon't get fooled by null bytes.\033[0m\n[i] Maybe, most of the data above is some padding noise (+= ch/al).\n[i] But, i guess, just keep scrolling and don't be lazy to scan... \033[1myou might encounteted a 'gold'.\033[0m\n\n{bold}[Example of Null Bytes]{reset}\n    // Loop recovery or code block containing constant junk:\n    {{\n        byte ptr [arg2] += ch;  <-- repetition\n        byte ptr [arg4] += al;  <-- 00 00 padding byte\n    }}\n\n{bold}[Example of active code]{reset}\n    // Real program logic or encryption functions found:\n    {{\n        eax ^= 0x34327800;      <-- good\n        if (!(param_1 == eax))  <-- control flow conditional check\n    }}\n")      

        return "\n".join(lines)
