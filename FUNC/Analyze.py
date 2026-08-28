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

class Analyze:
    def __init__(self, instance):
        self.shell = instance

    def runXREF(self, args):
        target = self.shell.base_address + self.shell.cursor
        if args and isinstance(args, list) and len(args) > 0:
            try:
                target = int(str(args[0]).strip(), 16)
            except ValueError:
                pass

        lines = [f"\n[\033[1mINFO\033[0m] scanning XREF for address: {hex(target)}..."]
        found = 0

        self.shell.cs.detail = True
        bold, reset, white, magenta, red, cyan = self.shell.BOLD, self.shell.RESET, self.shell.WHITE, self.shell.MAGENTA, self.shell.RED, self.shell.CYAN

        for insn in self.shell.cs.disasm(self.shell.binary_data, self.shell.base_address):
            mnemonic = insn.mnemonic        

            if not (mnemonic.startswith('j') or mnemonic.startswith('b') or mnemonic in ['call', 'bl', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz', 'adr', 'adrp']):
                continue

            clean_op = insn.op_str.replace("#", "")
            match_obj = re.search(r'0x[0-9a-fA-F]+', clean_op)

            destination = None
            if match_obj:
                try:
                    if "rip" in clean_op:
                        destination = insn.address + insn.size + int(match_obj.group(0), 16)
                    else:
                        destination = int(match_obj.group(0), 16)
                except:
                    pass

            if destination == target:
                is_jmp = mnemonic.startswith('j') or (mnemonic.startswith('b') and mnemonic != 'bl') or mnemonic in ['br', 'cbz', 'cbnz', 'tbz', 'tbnz']
                is_call = mnemonic in ['call', 'bl', 'blr']

                if is_jmp:
                    color, flow = red, "[JMP]"
                elif is_call:
                    color, flow = magenta, "[CALL]"
                else:
                    color, flow = cyan, "[REF]"

                lines.append(f"  {white}{flow}{reset} Found at {hex(insn.address)} -> ({color}{bold}{mnemonic}{reset} {insn.op_str})")
                found += 1


        if found == 0:
            lines.append("[\033[1mERROR\033[0m] yey, no external XREF found for this address.")

        lines.append("")
        return "\n".join(lines)    

    def EntropyMap(self):
        size = self.shell.file_size            
        block = 65536 if size > 5000000 else (4096 if size > 1000000 else (2048 if size > 500000 else 512))

        lines = [
            f"\n[\033[1mINFO\033[0m] shannon entropy Analysis (Block Size: {block} bytes)", 
            "Block\tVirtual Addr\tScore\t\tStatus / Graph", 
            "-" * 75
        ]

        red, yellow, green, bold, reset = self.shell.RED, self.shell.YELLOW, self.shell.GREEN, self.shell.BOLD, self.shell.RESET
        charts = ["█" * int(e * 3.5) for e in [x * 0.05 for x in range(161)]]

        for index in range(0, size, block):
            chunk = self.shell.binary_data[index : index + block]
            entropy = self.shell.calculate_entropy(chunk)           

            chart = charts[min(160, max(0, int(entropy * 20)))]
            vaddr = self.shell.base_address + index
            number = index // block

            status = f"{red}{bold}[PACKED]{reset} {red}{chart}{reset}" if entropy > 6.8 else (f"{yellow}[CODE]  {reset} {yellow}{chart}{reset}" if entropy > 4.2 else f"{green}[DATA]  {reset} {green}{chart}{reset}")

            lines.append(f"#{number}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{status}")

        lines.append("")
        return "\n".join(lines)
