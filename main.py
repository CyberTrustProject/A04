from sniff import sniffer
from hilbert import siteInput
import hashlib
import os

def main():
    count = 0
    if os.path.isfile('/var/log/suricata/malwaresquid/data/packet.mlsq'):
        os.remove('/var/log/suricata/malwaresquid/data/packet.mlsq')
    else:
        pass
    while True:
        pcap = os.listdir("/home/selks-user/pcap/pcap578/")
        pcap = "/home/selks-user/pcap/pcap578/" + pcap[count]
        print("Current pcap: ", pcap)
        pcapSize = os.stat(pcap)
        eof = pcapSize.st_size
        print("EOF: ", eof)
        output = sniffer(count, pcap, eof)
        result = siteInput(output, 'image')
        print("Result: ", result)
        if round(float(result), 1) > 0.95:
            print("Malware detected? Yes")
            file = open('/var/log/suricata/malwaresquid/malware.log', 'ab')
            file.write(output)
            file.close()
            #file = open('/var/log/suricata/malwaresquid/images/tmp/image.jpg')
            #move termporary image to it's hash output
            file_hash = os.popen('md5sum /var/log/suricata/malwaresquid/images/tmp/image.jpg| while read sum file; do echo $sum; done').read()
            os.popen('mv /var/log/suricata/malwaresquid/images/tmp/image.jpg /var/log/suricata/malwaresquid/images/' + file_hash)
            #append malwaresquid eve.json to suricata alert
            file = open('/var/log/suricata/malwaresquid/eve.json', 'a')
            file.write('/var/log/suricata/eve.json')
            file.close()
        if os.path.isfile('/var/log/suricata/malwaresquid/data/packet.mlsq'): 
            os.remove('/var/log/suricata/malwaresquid/data/packet.mlsq')
        if os.path.isfile('/var/log/suricata/malwaresquid/eve.json'):
            os.remove('/var/log/suricata/malwaresquid/eve.json')
        print("Malware detected? No")
        count = count + 1
main()
