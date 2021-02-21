"""
Management Frame Doom (M.F. DOOM): This project aims to provide a form of covert communications between two nodes via WiFi Management Frames

Author: Axel Persinger
License: MIT License
"""


"""
Imported Libraries

scapy - Networking/Packet library
argparse - Argument parsing library
golay - Golay Coding
"""
import scapy.layers
import scapy.layers.dot11
import scapy.sendrecv
import golay


def gen_proberequest(msg: bytes, src_addr: str = "ff:ff:ff:ff:ff:ff") -> scapy.packet:
    """
    Generates a probe request with a given message

    :param msg: Message to embed in packet
    :type msg: bytes
    :param src_addr: Source address for the probe request, defaults to "ff:ff:ff:ff:ff:ff"
    :type src_addr: str, optional

    :return: Generated scapy packet
    :rtype: scapy.packet
    """
    pkt = scapy.layers.dot11.RadioTap(
        # Default Args
    ) / scapy.layers.dot11.Dot11(
        type=0, subtype=4, FCfield=0x4000, cfe=0, ID=0, SC=0, addr1='ff:ff:ff:ff:ff:ff', addr2=src_addr, addr3='ff:ff:ff:ff:ff:ff', addr4=None
    ) / scapy.layers.dot11.Dot11ProbeReq(
        # Default Args
    ) / scapy.layers.dot11.Dot11Elt(
        info=msg, ID=0x45, len=len(msg) # 0x45 - Time Advertisement
    )
    return pkt


def gen_proberesponse(msg: bytes, src_addr: str = "ff:ff:ff:ff:ff:ff") -> scapy.packet:
    """
    Generates a probe response with a given message

    :param msg: Message to embed in packet
    :type msg: bytes
    :param src_addr: Source address for the probe response, defaults to "ff:ff:ff:ff:ff:ff"
    :type src_addr: str, optional

    :return: Generated scapy packet
    :rtype: scapy.packet
    """
    pkt = scapy.layers.dot11.RadioTap(
        # Default Args
    ) / scapy.layers.dot11.Dot11(
        type=0, subtype=4, FCfield=0x4000, cfe=0, ID=0, SC=0, addr1='ff:ff:ff:ff:ff:ff', addr2=src_addr, addr3='ff:ff:ff:ff:ff:ff', addr4=None
    ) / scapy.layers.dot11.Dot11ProbeResp(
        # Default Args
    ) / scapy.layers.dot11.Dot11Elt(
        info=msg, ID=0x45, len=len(msg) # 0x45 - Time Advertisement
    )
    return pkt


def extract_msg(pkt: scapy.packet) -> bytes:
    """
    Extracts an encoded, encrypted message from a Probe Request/Response packet

    :param pkt: packet that contains the message
    :type pkt: scapy.packet
    :return: message
    :rtype: bytes
    """
    # if not
    dot11elt = pkt.getlayer(scapy.layers.dot11.Dot11Elt)
    while dot11elt and dot11elt.ID != 0x45:
        dot11elt = dot11elt.payload.getlayer(scapy.layers.dot11.Dot11Elt)
    
    if not dot11elt: # Will be None if nothing was found, so return
        return

    # We now know that this is a Time Advertisement packet
    # Grab the info from it, decrypt it, decode it
    return dot11elt.info


class Sniffer():
    """
    Defines the Sniffer class. This is mainly done so we can run the process_proberequest with things like a password for the XOR encryption
    """
    password = b''


    def process_proberequest(self, pkt: scapy.packet):
        """
        Receives each packet and determines if it's a probe request, if it is, and it matches our signature, we respond to it.
        Adapted from https://gist.github.com/dropmeaword/42636d180d52e52e2d8b6275e79484a0

        :param pkt: Packet intercepted
        :type pkt: scapy.packet
        """    
        msg = extract_msg(pkt)
        print('>', msg)