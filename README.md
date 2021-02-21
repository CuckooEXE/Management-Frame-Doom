<p align="center" width="100%">
    <img width="33%" src="https://raw.githubusercontent.com/CuckooEXE/Management-Frame-Doom/main/imgs/management-frame-doom.png"> 
</p>


# Management Frame Doom

This project embeds infiltration and exfiltration data in valid WiFi managemement frames. This allows an attacker in proximity to an attacker-controlled client to have bi-directional communications in a method that would be nearly impossible for defenders to pick up on.

## Name

M.F. Doom is a fantastic artist you should listen to, I named this project in tribute to them.

# Theory

WiFi uses special packets called "management frames" to control the communications between clients and Access Points. Simply put, management frames are things like "Hey I want to join your network!" and "Hi, I'm broadcasting WiFi with this SSID on this channel", etc.

What if we could stuff extra attacker-defined data into these packets? No one would ever think to look in them, right?

## Management Frames



## Probe Frames

Probe frames are sent by clients (a.k.a. your phone or computer) to see what WiFis are in-range, and what protocols they support. Imagine walking into a room and yelling "WHO IS HERE, AND DO YOU SPEAK MY LANGUAGE?", that's a "probe request", essentially. In response, "probe response" packets are sent by APs that support your language.

## Probe Request

It's fairly handy that we can actually have the attacker poll and wait for a communication than the other way around. A lot of time, if your implant/malware needs to poll and wait for a message, it makes it much easier to find. Since Probe Requests initiate the communications, we can just start sending data out and assume the attacker receives it (or if we really want to, we can implement a SYN-SYN/ACK-ACK model).


![Probe Request](imgs/image.png)

Refering to the image above, we can start understanding some of the information:

**IEE 802.11 Probe Request:** This is the Probe Request Management frame basically saying "Hey this is a probe request"
1. Type/Subtype: This will always be 0x4 for a probe request
2. Frame Control Version: Version is always 0x00, Type is always 0x00, and Subtype is always 0x04
3. Flags: This will always be 0x00 for our purposes
4. Receiver Address: This will always be `ff:ff:ff:ff:ff:ff` for probe requests
5. Destination Address: This will always be `ff:ff:ff:ff:ff:ff` for probe requests
6. Transmitter Address: This needs to be our interface's MAC if we want to receive the request. We could set this to another address if we have the interface in monitor mode, however I want to see if this project works without root.
7. Source Address: This needs to be our interface's MAC if we want to receive the request. We could set this to another address if we have the interface in monitor mode, however I want to see if this project works without root.
8. BSS Id: This will always be `ff:ff:ff:ff:ff:ff` for probe requests
****
**IEEE 802.11 Wireless Management:** This is where the information we want to stuff will go. This information is all decided by the client and even supports "extended" information. This handy image from MRN-CCIEW explains this section:

![Wireless Management Packet](https://mrncciew.files.wordpress.com/2014/10/cwap-probe-10.png)

So looking through the various Tags we can send over in a Probe Request, I'm looking for something pretty innocuous that would allow stuff more data, and I ended up with Tag Number 0x45 "Time Advertisement".

## Probe Response

Probe responses come from the Access Points as they receive the Probe Requests and determine they can indeed connect. Well, what if we controlled the AP, and what if we only determine that our client can connect. 


# WarDriver

`wardriver.py` is just a [wardriving](https://en.wikipedia.org/wiki/Wardriving) utility I built to collect 802.11 Probe Frame Parameters/Tags. It requires access to a MongoDB instance to add items to, to spin up a MongoDB server quickly, you can follow this guide:

```bash
# Install the MongoDB python library
pip install pymongo

# Following https://docs.mongodb.com/manual/tutorial/install-mongodb-on-debian/
wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.4 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo systemctl daemon-reload
sudo systemctl enable mongod
sudo systemctl start mongod
```

Then you can run the script:

```bash

$ sudo python3 wardriver.py --iface wlan0mon --db localhost
Session Results:
  ID    Count
----  -------
   0        1
   1        1
   3        1
  45        1
  50        1
 127        1
 191        1
 107        1
  59        1
   5        1
   7        1
  42        1
  48        1
  70        1
  61        1
 221        1
All Results:
  ID    Count
----  -------
  61        2
  70        2
  42        2
   7        2
  48        2
   5        2
 107        3
  59        5
 221        7
 191       10
 127       16
   3       16
  45       20
  50       23
   1       23
   0       23
```