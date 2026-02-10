import socket
import sys
from datetime import datetime

# Target Definition (Replace with your own lab IP or localhost for safety)
TARGET_IP = "192.168.1.1" 

def scan_target(target):
    print(f"[*] Starting scan on host: {target}")
    print(f"[*] Time started: {str(datetime.now())}")
    print("-" * 50)

    try:
        # Scan common ports (1 to 1024)
        for port in range(1, 1025):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1) # Timeout creates speed vs accuracy trade-off
            
            # Returns 0 if connection succeeds
            result = s.connect_ex((target, port))
            
            if result == 0:
                print(f"[+] Port {port} is OPEN")
                grab_banner(s, port)
            s.close()
            
    except KeyboardInterrupt:
        print("\n[!] Exiting Program.")
        sys.exit()
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("\n[!] Could not connect to server.")
        sys.exit()

def grab_banner(s, port):
    try:
        # Send a simple byte to trigger a response
        s.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = s.recv(1024).decode().strip()
        print(f"    |_ Service Banner: {banner}")
    except:
        print("    |_ No banner retrieved")

if __name__ == "__main__":
    scan_target(TARGET_IP)
