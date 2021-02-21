"""
wardriver.py - Collects 802.11 Management Frame Tags/Parameters for analysis

Author: Axel Persinger
License: MIT License
"""


"""
Imported Libraries

argparse - Argument parser
pymongo - MongoDB library
threading - Threading library for console output
time - Sleep
tabulate - Pretty output tables
scapy - Python Networking library for sniffing
"""
import argparse
import pymongo
import threading
import time
import tabulate
import scapy.layers
import scapy.layers.dot11
import scapy.sendrecv
import scapy.utils

"""
Global Variables

_client - MongoDB Client
_stats - Packet capture statistics
"""
_client = None
_stats = {}


def console():
    """
    Outputs statistics of captured packets
    """
    while True:
        # Clear the screen
        print("\033c\033[3J", end='')
        
        # Aggregate results from DB
        results = _client.MFDoom.WarDriver.aggregate([
            {"$group": {"_id": "$TagID", "count": {"$sum": 1}}},
            { "$sort": { "count": -1 } }
        ])
        
        # Print current session results
        print("Session Results:")
        print(tabulate.tabulate(sorted(_stats.items(), key=lambda x: x[1]), headers=["ID", "Count"]))
        print()
        # Print global results
        print("All Results:")
        print(tabulate.tabulate(sorted([(i['_id'], i['count']) for i in results], key=lambda x: x[1]), headers=["ID", "Count"]))

        time.sleep(3)


def log_layers(pkt: scapy.packet):
    """
    Logs the various 802.11 Tag Layers in the packet

    :param pkt: Packet that was sniffed
    :type pkt: scapy.packet
    """
    global _stats

    dot11elt = pkt.getlayer(scapy.layers.dot11.Dot11Elt)
    while dot11elt:
        # print('ID:', dot11elt.ID, 'INFO:', dot11elt.info)
        
        # Update session statistics
        if str(dot11elt.ID) in _stats:
            _stats[str(dot11elt.ID)] += 1
        else:
            _stats[str(dot11elt.ID)] = 1

        # Update DB
        _client.MFDoom.WarDriver.insert_one({
            'TagID': dot11elt.ID,
            'TagInfo': dot11elt.info
        })

        # Get next layer
        dot11elt = dot11elt.payload.getlayer(scapy.layers.dot11.Dot11Elt)


def main():
    global _client
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--iface', type=str, required=True, action='store', help="Interface to send/receive on")
    parser.add_argument('-d', '--db', type=str, required=True, action='store', help="Database connection string for MongoDB instance")
    args = parser.parse_args()

    # Connect to the DB
    _client = pymongo.MongoClient(args.db)

    # Start the console-logger
    threading.Thread(target=console).start()
    
    # Sniff the packets
    scapy.sendrecv.sniff(
        iface=args.iface, 
        lfilter=lambda pkt: pkt.haslayer(scapy.layers.dot11.Dot11Elt),
        prn=log_layers,
    )


if __name__ == '__main__':
    main()