import sys
import re
import socket
from scapy.all import (
    rdpcap, sniff, IP, TCP, UDP, ICMP, Raw, IFACES, get_working_ifaces
)

# -------------------------------------------------------------------
# 🔥 ADVANCED ATTACK DETECTION
# -------------------------------------------------------------------
def detect_attacks(payload):
    patterns = {
        "SQL Injection": [
            r"(?i)union\s+select",
            r"(?i)or\s+1=1",
            r"(?i)drop\s+table",
            r"(?i)insert\s+into",
            r"(?i)--"
        ],
        "XSS": [
            r"(?i)<script.*?>.*?</script>",
            r"(?i)javascript:",
            r"(?i)onerror=",
            r"(?i)alert\("
        ],
        "Command Injection": [
            r";\s*\w+",
            r"\|\s*\w+",
            r"&&\s*\w+"
        ],
        "Directory Traversal": [
            r"\.\./",
            r"\.\.\\"
        ]
    }

    detected = []

    for attack, regex_list in patterns.items():
        for pattern in regex_list:
            if re.search(pattern, payload):
                detected.append(attack)
                break

    return detected


# -------------------------------------------------------------------
# 🔥 SEVERITY CLASSIFICATION
# -------------------------------------------------------------------
def classify_severity(attacks):
    if not attacks:
        return "Low"

    if "SQL Injection" in attacks or "Command Injection" in attacks:
        return "High"

    if "XSS" in attacks:
        return "Medium"

    return "Low"


# -------------------------------------------------------------------
# 📦 OFFLINE PCAP ANALYSIS
# -------------------------------------------------------------------
def process_packets(packets):
    results = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        payload = ""
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors="ignore")
            except:
                pass

        attacks = detect_attacks(payload)
        severity = classify_severity(attacks)

        if attacks:
            results.append({
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "attacks": attacks,
                "severity": severity,
                "payload": payload[:100]
            })

    return results


def analyze_packets(pcap_file):
    packets = rdpcap(pcap_file)
    return process_packets(packets)


# -------------------------------------------------------------------
# 🌐 INTERFACE DETECTION
# -------------------------------------------------------------------
def get_interface_for_ip(target_ip):
    local_ip = None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        pass

    if local_ip:
        for iface_name, iface_obj in IFACES.items():
            if iface_obj.ip == local_ip:
                return iface_name

    for iface_name, iface_obj in IFACES.items():
        if "VMware" in iface_obj.description:
            return iface_name

    working = get_working_ifaces()
    if working:
        return working[0].name

    return None


# -------------------------------------------------------------------
# 🚨 LIVE PACKET CAPTURE
# -------------------------------------------------------------------
def live_capture(target_ip, count=10, iface=None, timeout=15):
    captured = []

    if iface is None:
        iface = get_interface_for_ip(target_ip)

    print(f"[*] Sniffing on {iface} for {target_ip}", file=sys.stderr)

    def process_packet(pkt):
        if IP not in pkt:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst

        if src != target_ip and dst != target_ip:
            return

        proto = "OTHER"
        src_port = dst_port = flags = "N/A"

        if TCP in pkt:
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)

        elif UDP in pkt:
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        elif ICMP in pkt:
            proto = "ICMP"

        payload = ""
        if Raw in pkt:
            try:
                payload = pkt[Raw].load.decode(errors="ignore")[:100]
            except:
                payload = str(pkt[Raw].load)[:100]

        attacks = detect_attacks(payload) if payload else []
        severity = classify_severity(attacks)

        # 🚨 Suspicious ports detection
        suspicious_ports = [4444, 1337, 6666]
        port_flag = src_port in suspicious_ports or dst_port in suspicious_ports

        suspicious = True if attacks or port_flag else False

        captured.append({
            "src": src,
            "dst": dst,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
            "length": len(pkt),
            "payload": payload if payload else "No payload",
            "suspicious": suspicious,
            "attacks": attacks if attacks else ["None"],
            "severity": severity,
            "summary": pkt.summary()
        })

    try:
        sniff(
            filter=f"host {target_ip}",
            prn=process_packet,
            count=count,
            timeout=timeout,
            iface=iface,
            store=False
        )

    except PermissionError:
        return {"error": "Run as Administrator", "packets": []}

    except OSError:
        try:
            sniff(
                filter=f"host {target_ip}",
                prn=process_packet,
                count=count,
                timeout=timeout,
                store=False
            )
        except Exception as e:
            return {"error": str(e), "packets": []}

    except Exception as e:
        return {"error": str(e), "packets": []}

    return {
        "target_ip": target_ip,
        "packets_captured": len(captured),
        "suspicious_count": sum(1 for p in captured if p["suspicious"]),
        "packets": captured
    }