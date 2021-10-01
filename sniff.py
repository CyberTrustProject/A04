import socket
import sys
import os
from datetime import datetime
from struct import unpack
from hilbert import siteInput
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def eth_addr(input):
    # Convert string data input into dash seperated hex values
    formatted = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:" % (input[0], input[1], input[2], input[3], input[4], input[5])
    return formatted

def eveLog(timestamp, source_addr, source_port, dest_addr, dest_port, eth_protocol):
    log = {"Malwaresquid": "Detection", "timestamp": timestamp, "event_type": "alert",
           "src_ip": source_addr, "src_port": source_port, "dest_ip": dest_addr,
           "dest_port": dest_port, "proto": eth_protocol, "alert": {"action": "allowed",
           "gid": 1, "signature_id": "test", "rev": 9, "signature": "Potential Malware detected",
           "Category": "Unknown", "severity": 1 }}
    file = open('/var/log/suricata/malwaresquid/eve.json', 'a')
    file.write(str(log)+"\n")
    file.close

def macLog(start, source_mac, dest_mac, eth_protocol):
    log = {"MAC Log: " : '', "Start time" : start, "Source MAC Address" : source_mac,
            "Destination MAC Address" : dest_mac, "Ethernet Protocol": eth_protocol}
    file = open('/var/log/suricata/malwaresquid/malwaresquid.log', 'a')
    file.write(str(log)+"\n")
    file.close()

def ipLog(version, iphl, ttl, protocol, source_addr, dest_addr):
    log = {"IP Log" : '', "Version" : version, "IP Header Length" : iphl,
            "TTL" : ttl, "Protocol" : protocol, "Source Address" : source_addr,
            "Destination Address": dest_addr}
    file = open('/var/log/suricata/malwaresquid/malwaresquid.log', 'a')
    file.write(str(log)+"\n")
    file.close()

def tcpLog(source_port, dest_port, seq, ack, tcph):
    log = {"TCP Log" : '', "Source Port" : source_port, "Destination Port" : dest_port,
            "Sequence Number" : seq, "Acknowledgement" : ack, "TCP Header Length": tcph}
    file = open('/var/log/suricata/malwaresquid/malwaresquid.log', 'a')
    file.write(str(log)+"\n")
    file.close()

def icmpLog(icmp_type, code, checksum):
    log = {"ICMP Log" : '', "ICMP Type" : icmp_type, "Code" : code, "Checksum" : checksum}
    file = open('/var/log/suricata/malwaresquid/malwaresquid.log', 'a')
    file.write(str(log)+"\n")
    file.close()

def udpLog(source_port, dest_port, length, checksum):
    log = {"UDP Log" : '', "Source Port" : source_port, "Destination Port" : dest_port,
            "Length" : length, "Checksum" : checksum}
    file = open('/var/log/suricata/malwaresquid/malwaresquid.log', 'a')
    file.write(str(log)+"\n")
    file.close()

def sniffer(count, pcap, eof):
    while True:
        fileList = []
        #Set start time
        start = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        a = rdpcap(pcap)
        sessions = a.sessions()
        for session in sessions:
            for packets in sessions[session]:
                eth_length = 14
                packet = bytes(packets)
                eth_header = packet[:eth_length]
                eth = unpack('!6s6sH', eth_header)
                eth_protocol = socket.ntohs(eth[2])
                # Log the packet details
                macLog(start, eth_addr(packet[0:6]), eth_addr(packet[6:12]), str(eth_protocol))
                # Parse IP packets, IP Protocol number = 8
                if eth_protocol == 8:
                    # Parse IP Header
                    ip_header = packet[eth_length:20+eth_length]
                    iph = unpack('!BBHHHBBH4s4s', ip_header)
                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0xF
                    iph_length = ihl * 4
                    ttl = iph[5]
                    protocol = iph[6]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])
                    ipLog(str(version), str(ihl), str(ttl), str(protocol), str(s_addr), str(d_addr))
                    # TCP protocol
                    if protocol == 6:
                        t = iph_length + eth_length
                        tcp_header = packet[t:t+20]
                        # Unpack TCP packet
                        tcph = unpack('!HHLLBBHHH', tcp_header)
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4
                        # Log TCP packet
                        tcpLog(str(source_port), str(dest_port), str(sequence), str(acknowledgement), str(tcph_length))
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        # Get packet data
                        data = packet[h_size:]
                        # Write packet data to file
                        file = open('/var/log/suricata/malwaresquid/data/packet.mlsq', 'ab')
                        file.write(data)
                        file.close()
                    #ICMP Packets
                    elif protocol == 1:
                        i  = iph_length + eth_length
                        icmph_length = 4
                        icmp_header = packet[i:i+4]
                        # Unpack ICMP packet
                        icmph = unpack('!BBH', icmp_header)
                        icmp_type = icmph[0]
                        code = icmph[1]
                        checksum = icmph[2]
                        icmpLog(str(icmp_type), str(code), str(checksum))
                        h_size = eth_length + iph_length + icmph_length
                        data_size = len(packet) - h_size
                        # Get data from packet
                        data = packet[h_size:]
                        # Write packet data to file
                        file = open('/var/log/suricata/malwaresquid/data/packet.mlsq', 'ab')
                        file.write(data)
                        file.close()
                    # UDP Packets
                    elif protocol == 17:
                        u = iph_length + eth_length
                        udph_length = 8
                        udp_header = packet[u:u+8]
                        # Unpack UDP packet
                        udph = unpack('!HHHH', udp_header)
                        source_port = udph[0]
                        dest_port = udph[1]
                        length = udph[2]
                        checksum = udph[3]
                        udpLog(str(source_port), str(dest_port), str(length), str(checksum))
                        h_size = eth_length + iph_length + udph_length
                        data_size = len(packet) - h_size
                        # Get data from packet
                        data = packet[h_size:]
                        # Write data to file
                        file = open('/var/log/suricata/malwaresquid/data/packet.mlsq', 'ab')
                        file.write(data)
                        file.close()
                    else:
                        print("Error 1")
                if eth_protocol == 8:
                    eveLog(start, s_addr, source_port, d_addr, dest_port, eth_protocol)
                if os.path.isfile('/var/log/suricata/malwaresquid/data/packet.mlsq'):
                    statinfo = os.stat('/var/log/suricata/malwaresquid/data/packet.mlsq')
                    if statinfo.st_size >= eof:
                        file = open('/var/log/suricata/malwaresquid/data/packet.mlsq', 'rb')
                        filecontents = file.read()
                        return filecontents
                        count = count + 1
                    else:
                        pass
                else:
                    pass
        count=count+1
