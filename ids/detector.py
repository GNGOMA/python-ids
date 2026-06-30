from collections import defaultdict
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP

# --- Seuils de détection (ajustables) ---
PORT_SCAN_THRESHOLD = 10      # nb de ports distincts
PORT_SCAN_WINDOW = 10         # en secondes
BRUTE_FORCE_THRESHOLD = 8     # nb de tentatives sur le même port
BRUTE_FORCE_WINDOW = 15       # en secondes


def detect_port_scan(filepath):
    """Détecte les IPs qui sondent un grand nombre de ports distincts
    sur une cible donnée, dans une fenêtre de temps courte."""
    packets = rdpcap(filepath)

    # Pour chaque (src, dst), liste des (timestamp, port) où un SYN a été vu
    syn_events = defaultdict(list)

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        flags = pkt[TCP].flags
        is_syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
        if not is_syn_only:
            continue

        key = (pkt[IP].src, pkt[IP].dst)
        syn_events[key].append((float(pkt.time), pkt[TCP].dport))

    alerts = []
    for (src, dst), events in syn_events.items():
        events.sort()  # tri par timestamp
        n = len(events)

        for i in range(n):
            window_start = events[i][0]
            ports_in_window = set()
            j = i
            while j < n and events[j][0] - window_start <= PORT_SCAN_WINDOW:
                ports_in_window.add(events[j][1])
                j += 1

            if len(ports_in_window) >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    "type": "PORT_SCAN",
                    "src": src,
                    "dst": dst,
                    "distinct_ports": len(ports_in_window),
                    "window_seconds": PORT_SCAN_WINDOW,
                    "first_seen": window_start,
                })
                break  # une alerte par paire (src, dst) suffit

    return alerts


def detect_brute_force(filepath):
    """Détecte les IPs qui ouvrent un grand nombre de connexions
    vers le même port, dans une fenêtre de temps courte."""
    packets = rdpcap(filepath)

    # Pour chaque (src, dst, port), liste des timestamps où un SYN a été vu
    syn_events = defaultdict(list)

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        flags = pkt[TCP].flags
        is_syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
        if not is_syn_only:
            continue

        key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
        syn_events[key].append(float(pkt.time))

    alerts = []
    for (src, dst, port), timestamps in syn_events.items():
        timestamps.sort()
        n = len(timestamps)

        for i in range(n):
            window_start = timestamps[i]
            count = 1
            j = i + 1
            while j < n and timestamps[j] - window_start <= BRUTE_FORCE_WINDOW:
                count += 1
                j += 1

            if count >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "src": src,
                    "dst": dst,
                    "port": port,
                    "attempts": count,
                    "window_seconds": BRUTE_FORCE_WINDOW,
                    "first_seen": window_start,
                })
                break

    return alerts


def run_all_detections(filepath):
    return {
        "port_scans": detect_port_scan(filepath),
        "brute_forces": detect_brute_force(filepath),
    }
