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

class Shred:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):        
        binary = self.shell.binary_data
        base = self.shell.base_address
        size = self.shell.file_size
        arch = getattr(self.shell, 'arch_type', 'x86_64')

        bold = getattr(self.shell, 'BOLD', '\033[1m')
        reset = getattr(self.shell, 'RESET', '\033[0m')
        cyan = getattr(self.shell, 'CYAN', '\033[96m')
        yellow = getattr(self.shell, 'YELLOW', '\033[93m')

        lines = [f"\n[{bold}INFO{reset}] runinng binary 'shredding' sequences.\n"]           
        lines.append(f"[{bold}INFO{reset}] scanning global execution mapping functions.\n")

        all_funcs = []        
        idx = binary.find(b"\x55\x48\x89\xE5")
        while idx != -1:
            all_funcs.append(idx)
            idx = binary.find(b"\x55\x48\x89\xE5", idx + 1)            

        idx = binary.find(b"\xFF\x43\x00\xD1")
        while idx != -1:
            all_funcs.append(idx)
            idx = binary.find(b"\xFF\x43\x00\xD1", idx + 1)

        all_funcs = sorted(list(set(all_funcs)))
        lines.append(f"[INFO*] discovered: {bold}{len(all_funcs)}{reset} native function subroutines.")

        if all_funcs:           
            closest_offset = min(all_funcs, key=lambda x: abs(x - self.shell.cursor))
            target_vaddr = base + closest_offset
            lines.append(f"[\033[1mINFO*\033[0m] target lock     : auto-selected nearest function cluster boundary.")
        else:
            target_vaddr = base + self.shell.cursor
            lines.append(f"[\033[1mINFO*\033[0m] target lock     : no distinct signatures found. falling back to cursor.")

        lines.append(f"[\033[1mINFO*\033[0m] localized address cursor : {hex(base + self.shell.cursor)}")
        lines.append(f"[\033[1mINFO*\033[0m] 'shredder' targeted code   : {cyan}{hex(target_vaddr)}{reset}")      

        target_chunk = binary[target_vaddr - base : (target_vaddr - base) + 64]      

        if arch == "aarch64":            
            branches_count = sum(1 for b in target_chunk if b in (0x14, 0x94, 0x35, 0xd6))
        else:           
            branches_count = sum(1 for b in target_chunk if b in (0x74, 0x75, 0xeb, 0xe8))

        if branches_count > 0:
            lines.append(f"[\033[1mINFO*\033[0m] flow density  : Found {yellow}{bold}{branches_count}{reset} active branch conditions / block markers inside target.\n")        

        return "\n".join(lines)
