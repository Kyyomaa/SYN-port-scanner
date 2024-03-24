from scapy.all import IP, TCP, ICMP
import sys
import logging
from threading import Thread, Lock
import time

'''
stealth port scanner. Sends a TCP syn, when it recieves a SYN-ACK, resents the connection.
'''

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
class Synscan():
    
    def __init__(self):
        self.ip = sys.argv[1]
        self.strport = sys.argv[2]
        self.endport = sys.argv[3]
        self.lock = Lock()
        self.start_time = time.time()

    def scan_port(self, port):
        packet = IP(dst=self.ip)/TCP(dport=port,flags="S")
        response = sr1(packet,timeout=0.5, verbose = 0)
        with self.lock:
            
            if response is None:
                #print('[-] Port ', port, ' no response (filtered or dropped)')    
                pass
            elif response.haslayer(TCP):
                if response[TCP].flags == 0x12: #SYN-ACK = OPEN
                    print ('[+] PORT: ', port,  ' IS OPEN')
                    rst_pck = IP(dst=self.ip)/TCP(dport=port, sport = response[TCP].dport, flags="R")
                    try:
                        send(rst_pck, verbose = 0)
                    except TimeoutError as e:
                        print('[TIMEOUT]: ', e)
                elif response.haslayer(TCP) and response.getlayer(TCP).flags ==0x14:
                    pass
                    #print ('[+] PORT ', port, ' IS CLOSED') #debug
                elif response.haslayer(ICMP):
                
                    if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        #print("Port:"+str(port)+" Filtered")
                        pass
    def start(self):
        threads = []
        print ('[+] SCANNING HOST: ', self.ip)
        for port in range(int(self.strport), int(self.endport)):
            thread = Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        totports = int(self.endport) - int(self.strport)
        #print ('scanned: ', totports, ' ports')
        print('Scanned ', totports, ' ports in %s seconds' 
              % (time.time() - self.start_time))

def main():
    ss = Synscan()
    ss.start()
    
    
if __name__ == '__main__':
    main()
