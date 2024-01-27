from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

# NetfilterQueue 인스턴스 생성
nfqueue = NetfilterQueue()


def packet_handler(packet):
    print("Packet processed:", packet)

    # print("RAW DATA:", packet.get_payload())

    # IP헤더, TCP 헤더 파싱
    ip_packet = IP(packet.get_payload())
    print("src IP:", ip_packet.src)
    print("dst IP:", ip_packet.dst)

    tcp_header = ip_packet[TCP]
    print("src port:", tcp_header.sport)
    print("dst port:", tcp_header.dport)
    
    if ip_packet.haslayer(Raw):
        payload = ip_packet[Raw].load
        print(payload)
        modified_payload = payload.replace(b"bob", b"BOB")
        ip_packet[Raw].load = modified_payload
        packet.set_payload(bytes(ip_packet))
    
    target_url = ip_packet.dst
    http_req = IP(dst=target_url) / TCP(dport=80) / Raw(load="GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_url))
    print("http req:", http_req)

    # packet에 대한 처리를 결정
    # packet.drop()
    packet.accept()


# 만든 큐를 커널에 등록해야 함
# 0번 큐에 nfqueue를 등록하고, 패킷이 담기면 packet_handler를 호출하도록 설정.
nfqueue.bind(0, packet_handler)

# 아래 코드를 실행한 뒤 대기
nfqueue.run()

# 종료 코드
print("종료중..")
nfqueue.unbind()

