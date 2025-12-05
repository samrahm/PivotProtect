
from scapy.all import sniff

def start_live_capture(gui_app, interface=None):
    """
    Capture live packets and append them to gui_app.live_packet_queue.
    """
    def process_packet(packet):
        try:
            pkt = {
                "src_ip": packet[0][1].src,
                "dst_ip": packet[0][1].dst,
                "dst_port": packet[0][2].dport if packet.haslayer("TCP") else 0,
                "protocol": packet[0][2].name if packet.haslayer("TCP") else "Other",
                "size": len(packet),
                "timestamp": packet.time
            }
            gui_app.live_packet_queue.append(pkt)
        except Exception as e:
            print("Packet processing error:", e)

    sniff(prn=process_packet, filter="ip", store=False, iface=interface)
