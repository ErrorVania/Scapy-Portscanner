#import logging
import sys,threading,multiprocessing
#logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import IP,TCP,ICMP,sr1,sr

if len(sys.argv) == 1:
        helpstr = """Usage: {}\n
        -normal | perform a normal TCP connect scan (default). [SYN_PORT->SYN_ACK->RST_ACK]
        -stealth | perform a stealth TCP scan. Is used to evade port scanning detection by firewalls [SYN_PORT->SYN_ACK->RST]
        -commonports | scan all commonly used ports with given method. [HTTP,HTTPS,SSH,FTP,MySQL...]
        -startport | set the starting port
        -endport | set the endport
        -target | set the target ip
        -threads | set the amount of threads to run (default = {}).

        -target is required.
        -startport and endport or -commonports is required

        Examples: 
                {} -stealth -commonports -target myserver.com
                {} -startport 70 -endport 90 -target myserver.com -threads 2
                {} -endport 200 -target myserver.com -normalscan
                """.format(sys.argv[0],multiprocessing.cpu_count(),sys.argv[0],sys.argv[0],sys.argv[0])
        print(helpstr)
        exit()
        




threads = []
threadcount = multiprocessing.cpu_count()
commonports = [80,443,21,22,110,995,143,993,25,26,587,3306]
customports = []


flag_normalscan = False
flag_stealthscan = False
flag_commonports = False
flag_customports = False
flag_morethreads = False
target = ""
startport = 0
endport = 0


def friendlyscanport(target):
        global customports

        while (len(customports) != 0):

                port = min(customports)
                customports.remove(port)

                packet = IP(dst=target)/TCP(dport=port,flags='S')
                response = sr1(packet,timeout=0.5,verbose=0)
                if response != None:
                        if response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
                                print("[!] Port #"+str(port)+" is open!")
                                sr(IP(dst=target)/TCP(dport=response.sport,flags='R'),timeout=0.5,verbose=0)
                else:
                        print("[X] Port #"+str(port)+" is closed.")
def friendlyscanport_stealth(target):
        global customports
        
        while (len(customports) != 0):
        
                port = min(customports)
                customports.remove(port)

                packet = IP(dst=target)/TCP(dport=port,flags='S')
                response = sr1(packet,timeout=10,verbose=0)

                if response == None:
                        print("[X] Port #"+str(port)+" is closed.")
                elif response.haslayer(TCP):
                        if response.getlayer(TCP).flags == 0x12:
                                send_rst = sr(IP(dst=target)/TCP(dport=port,flags='R'),timeout=10,verbose=0)
                                print("[!] Port #"+str(port)+" is open!")
                        elif response.getlayer(TCP).flags == 0x14:
                                print("[X] Port #"+str(port)+" is closed.")
                elif response.haslayer(ICMP):
                        if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                                print("[#] Port #"+str(port)+" is filtered.")













if "-normal" not in sys.argv and "-stealth" not in sys.argv:
        flag_normalscan = True
if "-normal" in sys.argv and "-stealth" not in sys.argv:
        flag_normalscan = True
elif "-normal" not in sys.argv and "-stealth" in sys.argv:
        flag_stealthscan = True
if "-commonports" in sys.argv and "-startport" not in sys.argv and "-endport" not in sys.argv:
        flag_commonports = True
elif "-commonports" not in sys.argv or "-startport" in sys.argv or "-endport" in sys.argv:
        flag_customports = True
if "-threads" in sys.argv:
        flag_morethreads = True
if flag_customports:
        index = 0
        for x in sys.argv:
                if x == "-startport":
                        startport = int(sys.argv[index + 1])
                if x == "-endport":
                        endport = int(sys.argv[index + 1])
                index+=1
if "-target" in sys.argv:
        index = 0
        for x in sys.argv:
                if x == "-target":
                        target = sys.argv[index+1]
                index+=1

if flag_morethreads:
        index = 0
        for x in sys.argv:
                if x == "-threads":
                        threadcount = int(sys.argv[index + 1])
                index+=1


if flag_commonports:
        print("Scanning "+target+" for common TCP ports with {} threads... (press CTRL+C to stop)\n".format(str(threadcount)))
        customports = commonports
        for x in range(0,threadcount):
                if flag_normalscan:
                        t = threading.Thread(target=friendlyscanport,args=(target,))
                        threads.append(t)
                elif flag_stealthscan:
                        t = threading.Thread(target=friendlyscanport_stealth,args=(target,))
                        threads.append(t)
elif flag_customports:
        print("Scanning with given parameters (ports {} - {}) with {} threads...".format(str(startport),str(endport),str(threadcount)))
        for x in range(startport,endport):
                customports.append(x)
                
        for x in range(0,threadcount):
                if flag_normalscan:
                        t = threading.Thread(target=friendlyscanport,args=(target,))
                        threads.append(t)
                elif flag_stealthscan:
                        t = threading.Thread(target=friendlyscanport_stealth,args=(target,))
                        threads.append(t)


for x in threads:
        x.start()
for x in threads:
        x.join()