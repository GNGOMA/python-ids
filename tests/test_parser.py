from scapy.all import rdpcap
from ids.parser import parse_all


def test_parse_all_returns_records():
    packets = rdpcap("tests/fixtures/sample.pcap")
    records = parse_all(packets)

    assert len(records) > 0
    assert all(r.src_ip and r.dst_ip for r in records)
    assert all(r.protocol in ("TCP", "UDP", "ICMP", "OTHER") for r in records)


def test_tcp_records_have_ports():
    packets = rdpcap("tests/fixtures/sample.pcap")
    records = parse_all(packets)
    tcp_records = [r for r in records if r.protocol == "TCP"]

    assert len(tcp_records) > 0
    assert all(r.src_port is not None and r.dst_port is not None for r in tcp_records)
