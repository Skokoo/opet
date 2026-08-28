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

class Hexdump:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):
        size = 128
        if args and isinstance(args, list) and len(args) > 0:
            try: size = int(args[0])
            except: pass

        cursor = self.shell.cursor
        binary = self.shell.binary_data

        chunk = binary[cursor : cursor + size]
        vaddr = self.shell.base_address + cursor

        white = self.shell.WHITE
        green = self.shell.GREEN
        red = self.shell.RED
        reset = self.shell.RESET      

        hex_fmt = [f"{white}00{reset} " if b == 0x00 else (f"{green}{b:02x}{reset} " if 0x20 <= b <= 0x7E else f"{red}{b:02x}{reset} ") for b in range(256)]
        asc_fmt = [f"{white}.{reset}" if b == 0x00 else (f"{green}{chr(b)}{reset}" if 0x20 <= b <= 0x7E else f"{red}.{reset}") for b in range(256)]

        lines = [
            f"\n[\033[1mINFO\033[0m] Hex Dump at {hex(vaddr)}", 
            f"  Offset      00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ASCII", 
            "-" * 75
        ]        

        for index in range(0, len(chunk), 16):
            sub = chunk[index : index + 16]
            length = len(sub)         
            hex_str = "".join(hex_fmt[b] if idx != 8 else " " + hex_fmt[b] for idx, b in enumerate(sub))
            asc_str = "".join(asc_fmt[b] for b in sub)

            if length < 16:
                hex_str += " " * ((16 - length) * 3 + (1 if length <= 8 else 0))

            lines.append(f"  {hex(vaddr + index)}  {hex_str.rstrip()}  {asc_str}")

        lines.append("-" * 75 + "\n")
        return "\n".join(lines)
