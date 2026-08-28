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

import bisect

class Seeker:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):        
        binary = self.shell.binary_data
        base = self.shell.base_address
        size = self.shell.file_size
        arch = getattr(self.shell, 'arch_type', 'x86_64')

        bold = getattr(self.shell, 'BOLD', '\033[1m')
        reset = getattr(self.shell, 'RESET', '\033[0m')
        yellow = getattr(self.shell, 'YELLOW', '\033[93m')
        cyan = getattr(self.shell, 'CYAN', '\033[96m')

        if not args:
            return f"\n[{bold}WARNING{reset}] Missing address target.\n"

        target = str(args[0]).strip()
        try:
            val = int(target, 16) if target.startswith("0x") else int(target)
        except ValueError:
            return f"\n[{bold}WARNING{reset}] Invalid address format.\n"

        if not (0 <= (val - base) <= size):
            return f"\n[{bold}WARNING{reset}] Address out of bounds.\n"

        points = []       
        if arch == "aarch64":            
            idx = binary.find(b"\xff\x43\x00\xd1")
            while idx != -1:
                points.append(base + idx)
                idx = binary.find(b"\xff\x43\x00\xd1", idx + 1)

            idx = binary.find(b"\xfd\x7b\xbf\xa9")
            while idx != -1:
                points.append(base + idx)
                idx = binary.find(b"\xfd\x7b\xbf\xa9", idx + 1)
        else:           
            idx = binary.find(b"\x55\x48\x89\xe5")
            while idx != -1:
                points.append(base + idx)
                idx = binary.find(b"\x55\x48\x89\xe5", idx + 1)

        points.sort()
        self.shell.cursor = val - base

        if not points:
            return f"Cursor synchronized to: {hex(val)}"

        index = bisect.bisect_left(points, val)

        if index < len(points) and points[index] == val:
            suggest = points[index]
        else:
            suggest = points[max(0, index - 1)]

        if val == suggest:
            return f"Cursor synchronized to: {hex(val)}"

        return (f"\nCursor synchronized to: {hex(val)} {yellow}{bold}[WARNING: Inside Data/Padding]{reset}\n"
                f"-> {bold}Nearest valid function entry point found at: {cyan}{hex(suggest)}{reset}\n")
