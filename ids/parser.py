from typing import Optional, List

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

from ids.models import PacketRecord

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA",
}


def parse_packet(pkt: Packet) -> Optional[PacketRecord]:
    """Transforme un paquet Scapy brut en PacketRecord normalisé.
    Retourne None si le paquet n'a pas de couche IP (on l'ignore)."""

    if IP not in pkt:
        return None

    proto_num = pkt[IP].proto
    record = PacketRecord(
        timestamp=float(pkt.time),
        src_ip=pkt[IP].src,
        dst_ip=pkt[IP].dst,
        protocol=PROTO_NAMES.get(proto_num, "OTHER"),
        length=len(pkt),
    )

    if TCP in pkt:
        tcp = pkt[TCP]
        record.src_port = tcp.sport
        record.dst_port = tcp.dport
        flags = tcp.flags
        record.syn = bool(flags & 0x02)
        record.ack = bool(flags & 0x10)
        record.fin = bool(flags & 0x01)
        record.rst = bool(flags & 0x04)
        record.psh = bool(flags & 0x08)
        record.payload_size = len(bytes(tcp.payload))

    elif UDP in pkt:
        udp = pkt[UDP]
        record.src_port = udp.sport
        record.dst_port = udp.dport
        record.payload_size = len(bytes(udp.payload))

        # Décodage DNS si c'est une requête (présence de DNSQR)
        if DNS in pkt and pkt.haslayer(DNSQR):
            try:
                query_name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                qtype = pkt[DNSQR].qtype
                record.dns_query = query_name
                record.dns_query_type = DNS_QTYPES.get(qtype, f"TYPE{qtype}")
            except Exception:
                pass  # paquet DNS malformé, on ignore silencieusement

    return record


def parse_all(packets) -> List[PacketRecord]:
    """Parse une liste de paquets Scapy en liste de PacketRecord,
    en filtrant les paquets sans couche IP."""
    records: List[PacketRecord] = []
    for pkt in packets:
        record = parse_packet(pkt)
        if record is not None:
            records.append(record)
    return records
