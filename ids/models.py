from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str          # "TCP", "UDP", "ICMP", ou "OTHER"
    length: int

    # Champs spécifiques TCP/UDP (None si non applicable)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # Flags TCP individuels (False par défaut)
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False

    # Champ DNS (rempli uniquement si le paquet est une requête/réponse DNS)
    dns_query: Optional[str] = None
    dns_query_type: Optional[str] = None

    # Taille du payload applicatif (au-delà des en-têtes réseau)
    payload_size: int = 0

    def is_syn_only(self) -> bool:
        """Vrai si c'est un SYN pur (ouverture de connexion),
        donc dst_port y est fiable comme port de service."""
        return self.syn and not self.ack

