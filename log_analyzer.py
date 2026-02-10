import re

# Mock Log Data (In a real scenario, you'd open a file like '/var/log/auth.log')
log_file_path = "server_logs.txt"

def analyze_logs(file_path):
    failed_attempts = {}
    suspicious_ips = []
    
    print("[*] Analyzing Log File for Brute Force Attempts...")

    # Regex to find 'Failed password' entries and capture the IP address
    # Example Log: "Feb 10 10:00:00 server sshd[123]: Failed password for root from 192.168.1.50 port 22"
    pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")

    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    if ip in failed_attempts:
                        failed_attempts[ip] += 1
                    else:
                        failed_attempts[ip] = 1

        # Logic to flag IPs with more than 3 failed attempts
        print("\n[!] SUSPICIOUS ACTIVITY REPORT:")
        print(f"{'IP Address':<20} {'Failed Attempts'}")
        print("-" * 35)
        
        for ip, count in failed_attempts.items():
            if count > 3:
                print(f"{ip:<20} {count}")
                suspicious_ips.append(ip)

        if not suspicious_ips:
            print("[+] No brute force patterns detected.")
            
    except FileNotFoundError:
        print(f"[!] Error: File {file_path} not found.")

if __name__ == "__main__":
    # To test this, create a dummy 'server_logs.txt' file in the same folder
    analyze_logs(log_file_path)
