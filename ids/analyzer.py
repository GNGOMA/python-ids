from collections import Counter
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt",
}


def analyze_pcap(filepath):
    packets = rdpcap(filepath)

    src_counter = Counter()
    dst_counter = Counter()
    port_counter = Counter()
    proto_counter = Counter()
    bytes_per_ip = Counter()
    total_packets = 0
    syn_count = 0

    for pkt in packets:
        if IP not in pkt:
            continue

        total_packets += 1
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)

        src_counter[src] += 1
        dst_counter[dst] += 1
        proto_counter[PROTO_NAMES.get(proto, f"proto_{proto}")] += 1
        bytes_per_ip[src] += length

        if TCP in pkt:
            flags = pkt[TCP].flags
            # On ne compte le port que sur les paquets d'ouverture de connexion
            # (SYN=1, ACK=0) → c'est le seul cas où dport est garanti d'être
            # le vrai port de service visé, pas un port éphémère client.
            is_syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
            if is_syn_only:
                syn_count += 1
                port_counter[pkt[TCP].dport] += 1
        elif UDP in pkt:
            # UDP n'a pas de notion de connexion, donc dport reste une
            # approximation — voir la limite documentée dans les insights.
            port_counter[pkt[UDP].dport] += 1

    return {
        "total_packets": total_packets,
        "syn_count": syn_count,
        "top_src": src_counter.most_common(5),
        "top_dst": dst_counter.most_common(5),
        "top_ports": port_counter.most_common(5),
        "proto_breakdown": proto_counter.most_common(),
        "top_bytes": bytes_per_ip.most_common(5),
    }


def print_report(stats, filepath):
    console = Console()
    console.print(f"\n[bold]Analyse de {filepath}[/bold]")
    console.print(f"Total de paquets IP : {stats['total_packets']}\n")

    table_src = Table(title="Top 5 IPs sources")
    table_src.add_column("IP")
    table_src.add_column("Paquets", justify="right")
    for ip, count in stats["top_src"]:
        table_src.add_row(ip, str(count))
    console.print(table_src)

    table_dst = Table(title="Top 5 IPs destinations")
    table_dst.add_column("IP")
    table_dst.add_column("Paquets", justify="right")
    for ip, count in stats["top_dst"]:
        table_dst.add_row(ip, str(count))
    console.print(table_dst)

    table_ports = Table(title="Top 5 ports de service (basé sur SYN)")
    table_ports.add_column("Port")
    table_ports.add_column("Service")
    table_ports.add_column("Connexions", justify="right")
    for port, count in stats["top_ports"]:
        service = COMMON_PORTS.get(port, "—")
        table_ports.add_row(str(port), service, str(count))
    console.print(table_ports)

    table_proto = Table(title="Répartition par protocole")
    table_proto.add_column("Protocole")
    table_proto.add_column("Paquets", justify="right")
    for proto, count in stats["proto_breakdown"]:
        table_proto.add_row(proto, str(count))
    console.print(table_proto)

    table_bytes = Table(title="Top 5 IPs par volume émis")
    table_bytes.add_column("IP")
    table_bytes.add_column("Octets", justify="right")
    for ip, total_bytes in stats["top_bytes"]:
        table_bytes.add_row(ip, f"{total_bytes:,}")
    console.print(table_bytes)


def generate_insights(stats):
    insights = []
    total = stats["total_packets"]

    if total == 0:
        return ["Aucun paquet IP trouvé dans ce fichier."]

    # 1. Concentration du trafic source
    top_src_ip, top_src_count = stats["top_src"][0]
    src_pct = (top_src_count / total) * 100
    if src_pct > 70:
        insights.append(
            f"⚠️  {top_src_ip} génère {src_pct:.0f}% du trafic total — "
            f"trafic très concentré sur une seule source, possible scan ou flood."
        )
    elif src_pct > 40:
        insights.append(
            f"ℹ️  {top_src_ip} domine le trafic source ({src_pct:.0f}%), "
            f"probablement le client principal de cette capture."
        )

    # 2. Ports inhabituels — uniquement fiable si on a des SYN observés
    if stats["syn_count"] == 0:
        insights.append(
            "⚠️  Aucune ouverture de connexion TCP (SYN) capturée — "
            "ce pcap commence probablement en milieu de session, "
            "donc l'analyse des ports de service n'est pas fiable ici."
        )
    else:
        unusual_ports = [
            (port, count) for port, count in stats["top_ports"]
            if port not in COMMON_PORTS
        ]
        if unusual_ports:
            port_list = ", ".join(str(p) for p, _ in unusual_ports)
            insights.append(
                f"🔍 Port(s) de service non standard : {port_list} (basé sur "
                f"{stats['syn_count']} ouvertures de connexion observées) — "
                f"à vérifier si ce n'est pas une appli connue de ton réseau."
            )

    # 3. Service dominant identifié
    if stats["syn_count"] > 0 and stats["top_ports"]:
        top_port, top_port_count = stats["top_ports"][0]
        port_pct = (top_port_count / stats["syn_count"]) * 100
        service = COMMON_PORTS.get(top_port, f"port {top_port}")
        if port_pct > 50:
            insights.append(
                f"📊 {port_pct:.0f}% des connexions ouvertes ciblent {service} — "
                f"capture probablement centrée sur cette activité."
            )

    # 4. Asymétrie de volume (gros uploader vs gros downloader)
    if len(stats["top_bytes"]) >= 2:
        top_ip, top_bytes = stats["top_bytes"][0]
        second_ip, second_bytes = stats["top_bytes"][1]
        if second_bytes > 0 and top_bytes / second_bytes > 5:
            insights.append(
                f"📦 {top_ip} émet {top_bytes:,} octets, soit plus de 5x le volume "
                f"de la 2e IP ({second_ip}) — possible transfert de fichier volumineux "
                f"ou exfiltration de données."
            )

    # 5. Diversité protocolaire
    if len(stats["proto_breakdown"]) == 1:
        proto_name = stats["proto_breakdown"][0][0]
        insights.append(
            f"📌 100% du trafic est en {proto_name} — capture mono-protocole, "
            f"typique d'une session unique plutôt que d'un trafic réseau général."
        )

    if not insights:
        insights.append("Aucun pattern particulier détecté — trafic globalement homogène.")

    return insights


def print_insights(insights):
    console = Console()
    text = "\n".join(insights)
    console.print(Panel(text, title="Conclusions", border_style="cyan"))
def print_alerts(detection_results):
    console = Console()

    port_scans = detection_results["port_scans"]
    brute_forces = detection_results["brute_forces"]

    if not port_scans and not brute_forces:
        console.print(Panel(
            "Aucune attaque détectée par les règles actuelles.",
            title="Alertes de sécurité",
            border_style="green",
        ))
        return

    table = Table(title="🚨 Alertes de sécurité détectées")
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Détail")

    for alert in port_scans:
        table.add_row(
            "[bold red]PORT SCAN[/bold red]",
            alert["src"],
            alert["dst"],
            f"{alert['distinct_ports']} ports distincts en {alert['window_seconds']}s",
        )

    for alert in brute_forces:
        table.add_row(
            "[bold yellow]BRUTE FORCE[/bold yellow]",
            alert["src"],
            f"{alert['dst']}:{alert['port']}",
            f"{alert['attempts']} tentatives en {alert['window_seconds']}s",
        )

    console.print(table)
