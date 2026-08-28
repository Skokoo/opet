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
import re

class BinaryGatherer:
    def __init__(self, data):
        self.raw = data
        self.size = len(data)

    def run_gather(self):
        size = self.size
        binary = self.raw             
        flat = " ".join([x.group().decode('ascii', errors='ignore').lower() for x in re.finditer(b"[\x20-\x7E]{4,}", binary)])

        compiler = "Unknown Compiler"
        linker = "Unknown Linker"
        format = "Raw Binary Data"
        architecture = "x86_64"
        language = "C / C++ or Native ASM"
        target = "Generic Environment"
        alerts = []

        if size >= 20:
            magic = binary[:4]
            if magic.startswith(b"\x7fELF"):
                format = "ELF (Linux)"
                architecture = "ARM64 (AArch64)" if binary[18] == 0xb7 else ("x86_64" if binary[18] == 0x3e else "x86 (32-bit)")
            elif magic.startswith(b"MZ"):
                format = "PE (Windows / DOS)"                
                try:
                    pe_offset = int.from_bytes(binary[0x3c:0x40], "little")
                    machine = int.from_bytes(binary[pe_offset+4:pe_offset+6], "little")
                    architecture = "ARM64" if machine == 0xaa64 else ("x86_64" if machine == 0x8664 else "x86 (32-bit)")
                except: pass
            elif magic.startswith(b"\xca\xfe\xba\xbe") or magic.startswith(b"\xcf\xfa\xed\xfe"):
                format = "Mach-O (Apple)"
                architecture = "ARM64" if binary[4] == 0x01 else "x86_64"

        compilers = {
            "gcc": ("GCC (GNU Compiler Collection)", "C / C++ or Native ASM"),
            "clang": ("Clang / LLVM", "C / C++ or Native ASM"),
            "msvc": ("MSVC (Microsoft Visual C++)", "C / C++ or Native ASM"),
            "microsoft visual c": ("MSVC (Microsoft Visual C++)", "C / C++ or Native ASM"),
            "mingw": ("MinGW (Windows)", "C / C++ or Native ASM"),
            "fpc": ("Free Pascal", "Pascal"),
            "free pascal": ("Free Pascal", "Pascal"),
            "go.go": ("Go Language Compiler", "Go (Golang)"),
            "runtime.gopanic": ("Go Language Compiler", "Go (Golang)"),
            "rustc": ("rustc (LLVM Backend)", "Rust"),
            "core::panicking": ("rustc (LLVM Backend)", "Rust"),
            "std::rt": ("rustc (LLVM Backend)", "Rust"),
            "pyi_rth_": ("PyInstaller Bundle", "Python (Frozen Binary)"),
            "pydata": ("PyInstaller Bundle", "Python (Frozen Binary)"),
            "libpython": ("Python Embeddable", "Python (Frozen Binary)")
        }

        for key, val in compilers.items():
            if key in flat:
                compiler, language = val
                if "go" in key or "rust" in key or "py" in key: break

        versions = re.findall(r'glibc_2\.[0-9]+', flat)
        target = f"Linux Kernel (Requires {max(tuple(versions)).upper()})" if versions else ("Linux Environment (Standard libc)" if "ld-linux" in flat else ("Windows OS Environment" if any(x in flat for x in ("kernel32.dll", "ntdll.dll")) else "Generic Environment"))
        linker = "GNU gold linker" if "gold" in flat else ("GNU ld (Standard Linux)" if "ld-linux" in flat else "Unknown Linker")

        protections = {
            "__stack_chk_fail": "Stack Canary (Anti-Buffer Overflow)",
            "upx!": "UPX Packing Detected (Compressed/Packed)",
            "mprotect": "Dynamic Memory / Shellcode Potential",
            "virtualprotect": "Dynamic Memory / Shellcode Potential",
            "ptrace": "Anti-Debug: ptrace (Linux Trace Trap)",
            "isdebuggerpresent": "Anti-Debug: Windows Debugger API",
            "checkremotedebuggerpresent": "Anti-Debug: Windows Debugger API"
        }
        alerts = [val for key, val in protections.items() if key in flat]

        lines = [
            "\n" + "="*60,
            f" [INFO] \033[1mMETADATA\033[0m",
            "="*60,
            f"  * Size   : {size} bytes",
            f"  * Format : {format}",
            f"  * Arch   : {architecture}",
            f"  * Lang   : {language}",
            f"  * Comp   : {compiler}",
            f"  * Target : {target}",
            f"  * Linker : {linker}"
        ]

        lines.append("[\033[1mWARNING\033[0m] Alerts/Protections:\n" + "\n".join(f"-> \033[1m{x}\033[0m" for x in alerts) if alerts else "[INFO] Alerts/Protections: None (Clean ASM)")
        lines.append("="*60 + "\n")
        return "\n".join(lines)
