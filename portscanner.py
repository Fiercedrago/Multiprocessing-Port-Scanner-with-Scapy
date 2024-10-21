import scapy.all as scapy
from multiprocessing import Pool, freeze_support

def scan_port(port, target):
    try:
        src_port = 1234  # Random port
        response = scapy.sr1(scapy.IP(dst=target)/scapy.TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=0)
        if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
            return port
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

def port_scan(target, ports):
    open_ports = []
    # Reduce the number of processes
    with Pool(processes=10) as pool:
        open_ports = pool.starmap(scan_port, [(port, target) for port in ports])
    return [p for p in open_ports if p]

if __name__ == '__main__':
    freeze_support()
    target = "100.0.0.1"
    target_ports = range(1, 1001)

    try:
        open_ports = port_scan(target, target_ports)
        if open_ports:
            print("Open ports: ", open_ports)
        else:
            print("No open ports found.")
    except Exception as e:
        print(f"Error during port scan: {e}")
