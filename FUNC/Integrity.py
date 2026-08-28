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

class Integrity:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):
        binary = self.shell.binary_data
        size = self.shell.file_size
        base = self.shell.base_address

        if size < 64:
            return "[\033[1mERROR\033[0m] Binary file too small to be a valid ELF structure."

        bold = getattr(self.shell, 'BOLD', '\033[1m')
        reset = getattr(self.shell, 'RESET', '\033[0m')
        white = getattr(self.shell, 'WHITE', '\033[97m')

        lines = [
            f"\n============================================================",
            f" [INFO] Anti-tamper & Binary integrity",
            f"============================================================",
            f"  * Target File Size : {size} bytes"
        ]

        # Offset 0x00-0x03: e_ident[0-3] (ELF magic number validation)
        if len(binary) < 4 or list(binary[:4]) != [0x7f, 0x45, 0x4c, 0x46]:           
            return f"[\033[1mWARNING\033[0m] Command 'ai' is optimized for ELF/Native .so binaries. Format mismatched."

        lines.append(f"  * ELF Magic Status : {bold}Valid/ok (7f 45 4c 46){reset}")

        # Offset 0x04: e_ident[EI_CLASS] (1=32bit, 2=64bit)
        # Offset 0x05: e_ident[EI_DATA] (1=smoll endian, 2=biggy endian)
        bit_mode = "64-bit" if binary[4] == 2 else ("32-bit" if binary[4] == 1 else "Unknown Bits")
        endian_mode = "Little-Endian" if binary[5] == 1 else ("Big-Endian" if binary[5] == 2 else "Unknown Endian")
        lines.append(f"  * Class / Encoding : {bold}{bit_mode} / {endian_mode}{reset}")

        # Offset 0x12: e_machine (target architecture instruction set)
        machine_code = binary[18]
        arch_map = {0x3e: "x86_64 (AMD64)", 0xb7: "AArch64 (ARM64)", 0x28: "ARM (32-bit)", 0x03: "Intel 80386 (x86)"}
        arch_name = arch_map.get(machine_code, f"Unknown (Code: {hex(machine_code)})")
        lines.append(f"  * Hardware Target  : {bold}{arch_name}{reset}")

        # Offset 0x10 (16): e_type (1=relocatable, 2=exec, 3=so)
        type_code = int.from_bytes(binary[16:18], "little")
        type_map = {1: "REL (Relocatable object file)", 2: "EXEC (Executable file)", 3: "DYN (Shared object / .so dynamic link library)"}
        type_name = type_map.get(type_code, f"Unknown Type ({type_code})")
        lines.append(f"  * Binary ELF Type  : {bold}{type_name}{reset}")

        # Offset 0x28 (40): start of section headers (e_shoff)
        # Offset 0x3a (58): number of section headers (e_shnum)
        shoff = int.from_bytes(binary[40:48], "little")
        shnum = int.from_bytes(binary[58:60], "little")

        corrupted = shoff >= size or (shoff + (shnum * 64) > size) if shnum > 0 else False       

        status_table = f"[{bold}INFO{reset}] Section Header Table points to invalid EOF bounds.{reset}" if corrupted else f"{bold}INTECT (Standard Linux Section Mapping){reset}"
        lines.append(f"  * Header Integrity : {status_table}")

        flat_str = binary.lower()
        is_stripped = b".symtab" not in flat_str and b".strtab" not in flat_str
        status_symbols = f"[{bold}INFO{reset}] Function names hidden by developer" if is_stripped else f"[{bold}INFO{reset}] Debug symbols available"
        lines.append(f"  * Symbol Visibility: {status_symbols}")

        has_rwx = b"mprotect" in flat_str or b"ptrace" in flat_str
        status_rwx = f"[{bold}WARNING{reset}] Contains dynamic injection or trace hooks primitives." if has_rwx else f"[{bold}INFO{reset}] No malicious hook signatures found"
        lines.append(f"  * Threat Indicators: {status_rwx}")

        has_upx = b"upx!" in flat_str
        status_upx = f"[{bold}WARNING{reset}] Packing layout signatures detected (UPX compression compressed)." if has_upx else f"[{bold}INFO{reset}] Native format templates layout unpacked"
        lines.append(f"  * Packer Signature : {status_upx}")

        verdict = f"[{bold}ALERT{reset}] This file shows anti analysis or tampering characteristics." if (corrupted or has_rwx or has_upx) else f"[{bold}INFO{reset}] Binary template structures comply with standard runtime rules."
        lines.append(f"  * Final verdict    : {verdict}\n")       

        return "\n".join(lines)
