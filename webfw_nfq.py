from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
import threading

# NetfilterQueue 인스턴스 생성
nfqueue = NetfilterQueue()

threat_words = [
    "<script>",
    "' or '",
    "\" or \""
]

def packet_handler(packet):
    print("Packet processed:", packet)

    # IP헤더, TCP 헤더 파싱
    ip_packet = IP(packet.get_payload())
    print("src IP:", ip_packet.src)
    print("dst IP:", ip_packet.dst)

    if ip_packet.haslayer(TCP):
        tcp_header = ip_packet[TCP]
        print("src port:", tcp_header.sport)
        print("dst port:", tcp_header.dport)
        # print("payload:", tcp_header.payload)
    
    if ip_packet.haslayer(Raw):
        payload = ip_packet[Raw].load.decode('utf-8', errors='replace')
        print("payload: ", payload)

        for word in threat_words:
            if word in payload:
                modified_payload = payload.replace(word, f"<!--{word}-->")
        
        modified_payload = payload.encode('utf-8')
        ip_packet[Raw].load = modified_payload
        packet.set_payload(bytes(ip_packet))
    else:
        print("ip packet has no Raw layer")

    # packet에 대한 처리를 결정
    # packet.drop()
    packet.accept()


def runQueue():
    nfqueue.run()


def unbindQueue():
    # 종료 코드
    print("종료중..")
    nfqueue.unbind()


def bindQueue():
    print("bindQueue() called")
    # 만든 큐를 커널에 등록해야 함
    # 0번 큐에 nfqueue를 등록하고, 패킷이 담기면 packet_handler를 호출하도록 설정.
    nfqueue.bind(0, packet_handler)
    # 아래 코드를 실행한 뒤 대기
    thread = threading.Thread(target=runQueue)
    thread.start()



