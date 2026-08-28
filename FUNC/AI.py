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

import os, json, subprocess, urllib.request, urllib.error, sys

def run_ai(path):
    if not os.path.isfile(path): return print(f"[\033[1mERROR\033[0m] file not found in path: \033[1m{path}\033[0m")

    print(f"[\033[1mINFO\033[0m] Loaded file : {path}\n")
    
    fn = os.path.basename(path)

    try:
        key = input("Enter Gemini api key: ").strip()
    except KeyboardInterrupt:
        print("[\033[1mINFO\033[0m] Keyboard Interrupted.") 
        sys.exit(0)
 
    if not key: return print("[\033[1mERROR\033[0m] Forgot to input the Gemini api key?", flush=True)

    print(f"[\033[1mINFO\033[0m] Extracting context for: \033[1m{fn}\033[0m.", flush=True)

    def run(cmd, to):
        try: return subprocess.run(cmd, capture_output=True, text=True, timeout=to).stdout.strip()
        except: return ""

    def dis():
        out = run(["objdump", "-d", "--no-show-raw-insn", path], 2).splitlines()
        pos = next((i for i, l in enumerate(out) if any(m in l for m in ["<main>:", "<_start>:"])), -1)
        return "\n".join(out[pos:pos+100] if pos != -1 else out[:100])

    str_data = "\n".join([s for s in run(["strings", "-n", "4", path], 2).splitlines() if len(s.strip()) > 4][:50])
    ctx = f"File Info:\n{run(['file', path], 2)}\n\nExtracted Strings:\n{str_data[:800]}\n\nDisassembly:\n{dis()[:1500]}"

    model = "gemini-3.7-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent?key={key}&alt=sse"

    make_payload = lambda history: json.dumps({
        "contents": history,
        "system_instruction": {"parts": [{"text": (
            "You are an 'elite' Reverse Engineering AI. Give a raw, technical vulnerability report. "
            "DO NOT USE MARKDOWN (NO **, NO ##, NO ```).\n\nBinary Context:\n" + ctx + "\n\n"
            "Acknowledge readiness shortly on your very first turn without metadata."
        )}]},
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 600}
    }).encode('utf-8')

    chat_history, is_initial = [], True

    while True:
        try:
            if is_initial:
                print(f"[\033[1mINFO\033[0m] Initializing session with {model}...", flush=True)
                chat_history.append({"role": "user", "parts": [{"text": "Load target context."}]})
                is_initial = False
            else:
                try:
                    user_input = input("\033[1;32mAsk > \033[0m").strip()
                except KeyboardInterrupt:
                    print("[\033[1mINFO\033[0m] Keyboard Interrupted.") 
                    sys.exit(0)

                if not user_input: continue
                if user_input.lower() in ['exit', 'quit', 'q']: break
                chat_history.append({"role": "user", "parts": [{"text": user_input}]})
                print("[\033[1mINFO\033[0m] thinking...", flush=True)

            req = urllib.request.Request(url, data=make_payload(chat_history), headers={"Content-Type": "application/json"})

            try:
                with urllib.request.urlopen(req, timeout=40) as res:
                    full_resp = ""
                    print("\n", end="", flush=True)

                    for raw_line in res:
                        line = raw_line.decode('utf-8').strip()
                        if line.startswith("data:"):
                            try:
                                chunk_text = json.loads(line[5:].strip())["candidates"][0]["content"]["parts"][0]["text"]
                                print(chunk_text, end="", flush=True)
                                full_resp += chunk_text
                            except (KeyError, IndexError, json.JSONDecodeError):
                                continue

                    clean_resp = full_resp.strip()
                    if clean_resp:
                        chat_history.append({"role": "model", "parts": [{"text": clean_resp}]})

                    print("\n", flush=True)

            except KeyboardInterrupt:
                print("\n\n[\033[1mINFO\033[0m] Keyboard Interrupted.")
                break

        except urllib.error.HTTPError as err: print(f"[\033[1mERROR\033[0m] HTTP {err.code}", flush=True)
        except Exception as err: print(f"[\033[1mERROR\033[0m] Fail: {err}", flush=True)           
