import struct
import sys

def read_global_header(f):
    global_header = f.read(24)
    magic_number = global_header[:4].hex()

    if magic_number == "d4c3b2a1":
        endian = "<"
    elif magic_number == "a1b2c3d4":
        endian = ">"
    else:
        raise ValueError("Unknow file format")
    
    return endian

def process_packets(f, endian):
    packets = []

    while True:
        header = f.read(16)
        if len(header)<16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", header)
        timestamp = ts_sec + ts_usec / 1_000_000

        data = f.read(incl_len)

        # ethernet check
        eth_type = struct.unpack(">H", data[12:14])[0]
        if eth_type != 0x0800:
            continue

        ip_start = 14

        protocol = data[ip_start + 9]

        ttl = data[ip_start+8]

        src_ip = ".".join(map(str, data[ip_start+12: ip_start+16]))
        dst_ip = ".".join(map(str, data[ip_start+16: ip_start+20]))

        packet = {
            "timestamp": timestamp,
            "protocol": protocol,
            "ttl": ttl,
            "src_ip": src_ip,
            "dst_ip": dst_ip
        }

        if protocol==1:
            icmp_type = data[ip_start+20]
            packet["icmp_type"] = icmp_type

        packets.append(packet)

    return packets

def identify_nodes(packets):
    source_ip = None
    destination_ip = None
    routers = []

    for p in packets:

        #outgoing packet (UDP or ICMP echo)
        if p["protocol"]==17 or (p["protocol"]==1 and p.get("icmp_type")==8):
            if source_ip is None:
                source_ip = p["src_ip"]
                destination_ip = p["dst_ip"]
        
        # ICMP replies from routers
        if p["protocol"]==1 and p.get("icmp_type")==11:
            routers.append(p["src_ip"])

        # final destination
        if p["protocol"]==1 and p.get("icmp_type")==3:
            destination_ip = p["src_ip"]

    routers = list(dict.fromkeys(routers))
    
    return source_ip, destination_ip, routers

def main():
    file = sys.argv[1]

    with open(file, "rb") as f:
        endian = read_global_header(f)
        packets = process_packets(f, endian)

    source_ip, destination_ip, routers = identify_nodes(packets)

    print("Source IP:", source_ip)
    print("Destination IP:", destination_ip)

    print("\nIntermediate routers:")
    for i, r in enumerate(routers, 1):
        print(f"router {i}: {r}")

main()


        