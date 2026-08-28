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

try:
    from Gather import BinaryGatherer
except ImportError:
    print("[\033[1mERROR*\033[0m] Gather.py cannot be imported inside INFO folder.")

class InfoValidator:
    def __init__(self, data):
        self.raw = data
        self.size = len(data)

    def eval_report(self, report):       
        text = False
        try:            
            sample = self.raw[:500]          
            if len(sample) > 0 and (sum(1 for x in sample if 32 <= x <= 126 or x in (9, 10, 13)) / len(sample)) > 0.9:
                text = True
        except:
            pass

        mask = {
            "Format :": "  * Format : Plain Text File (False Binary Mask Detected!)",
            "Comp   :": "  * Comp   : None (Text match only, not compiled)",
            "Linker :": "  * Linker : None",
            "Lang   :": "  * Lang   : None (Plain Text)",
            "Target :": "  * Target : None"
        }

        lines = [
            (mask[next(key for key in mask if key in line)] if text and any(key in line for key in mask)
             else (line.replace("UPX", "\033[91m\033[1m[CRITICAL] UPX\033[0m") if "UPX" in line and not text else line))
            for line in report.split("\n")
        ]

        return "\n".join(lines)

    def run_pipeline(self):       
        gatherer = BinaryGatherer(self.raw)
        return self.eval_report(gatherer.run_gather())
