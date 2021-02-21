"""
rat - This is an incredibly bad Remote Access Tool made to demonstrate communication via M.F. Doom

The point of this isn't the RAT part, it's just a showcase

Author: Axel Persinger
License: MIT License
"""


"""
Imported Libraries

golay - Golay encoding
mfdoom - Management Frame communication system
scapy.sendrecv - Send and recv packets with Scapy
subprocess - Execute commands and get STDOUT/STDIN
"""
import golay
import mfdoom
import scapy.sendrecv
import subprocess
import datetime


def main():
    i = 1
    while True:
        try:
            # Craft packet
            # msg = golay.xor(msg, b'Password123!@#')
            # msg = golay.encode(msg)
            # pkt = mfdoom.gen_proberequest(msg)
            
            # # Send packet and receive response
            # resp = scapy.sendrecv.srp1(pkt)

            
            # # msg = golay.xor(msg, self.password)
            # msg = golay.decode(msg)
            # print('>', msg)

            pkt = mfdoom.gen_proberequest("Packet {}: {}".format(i, datetime.datetime.now()))
            scapy.sendrecv.sendp(pkt)
            i+=1

            
        except:
            pass


if __name__ == '__main__':
    main()