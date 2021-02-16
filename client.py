"""
Management Frame Doom (M.F. DOOM): This project aims to provide a form of covert communications between two nodes via WiFi Management Frames

Author: Axel Persinger
License: MIT License
"""


"""
Imported Libraries

scapy - Networking/Packet library
argparse - Argument parsing library
"""
import scapy.layers
import scapy.layers.dot11
import scapy.sendrecv
import argparse


def send(msg: bytes, iface: str, no_wait: bool = False) -> bytes:
    """
    Sends the actual message, receives one response if not `no_wait`

    :param msg: Message to send, should be the response of `golay()`
    :type msg: bytes
    :param msg: Interface to use
    :type msg: str
    :param no_wait: Do not wait for a response, defaults to False
    :type no_wait: bool, optional
    :return: Response message
    :rtype: bytes
    """
    pkt = scapy.layers.dot11.RadioTap(
        # Default Args
    ) / scapy.layers.dot11.Dot11(
        type=0, subtype=4, FCfield=0x4000, cfe=0, ID=0, SC=0, addr1='ff:ff:ff:ff:ff:ff', addr2='48:d6:d5:cb:85:bf', addr3='ff:ff:ff:ff:ff:ff', addr4=None
    ) / scapy.layers.dot11.Dot11ProbeReq(
        # Default Args
    ) / scapy.layers.dot11.Dot11Elt(
        ID=0, info=b'Persinger WiFi'
    ) / scapy.layers.dot11.Dot11Elt(
        info=msg, ID=0x45, len=len(msg) # 0x45 - Time Advertisement
    )
    
    send_func = scapy.sendrecv.sendp if no_wait else scapy.sendrecv.srp1
    return send_func(pkt, iface=iface, verbose=0)


def golay_encode(msg: str) -> bytes:
    """
    Performs Golay message encoding

    :param msg: Message to send
    :type msg: str
    :return: Encoded bytes
    :rtype: bytes
    """
    # TODO: Implement this
    return msg.encode('utf-8')


def golay_decode(pkt: scapy.packet) -> list:
    """
    Performs Golay message decoding

    :param msg: Packet received to decode
    :type msg: scapy.packet
    :return: List of tuples in form of [(orig_msg, decoded_msg, errors), ...]
    :rtype: bytes
    """
    # First get the message itself:
    dot11elt = pkt.getlayer(scapy.layers.dot11.Dot11Elt)
    while dot11elt and dot11elt.ID != 0: # != 0x45:
        dot11elt = dot11elt.payload.getlayer(scapy.layers.dot11.Dot11Elt)

    msg = dot11elt #.?
    return msg.summary()
    # print(msg, type(msg), dir(msg))
    # return [(msg, msg.decode('ascii'), 0)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--iface', type=str, required=True, action='store', help="Interface to send/receive on")
    parser.add_argument('-d', '--data', type=str, required=False, action='store', help="Message to send, if not provided, an interactive session starts")
    parser.add_argument('-n', '--no-wait', required=False, action='store_true', help="Send message and don't wait for a response")
    args = parser.parse_args()

    if args.data:
        response = send(golay_encode(args.data), args.iface, no_wait=args.no_wait)
        if not args.no_wait:
            response = golay_decode(response)
            print('<', response)

    else:
        try:
            while True:
                data = input('> ')
                response = send(golay_encode(data), args.iface, no_wait=False)
                response = golay_decode(response)
                print('<', response)
        except KeyboardInterrupt:
            print("[*] INFO: Caught Keyboard Interrupt, exiting...")


if __name__ == '__main__':
    main()