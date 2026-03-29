import struct
import math
import sys

class IP_Header:
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.identification = 0
        self.flags = 0
        self.frag_offset = 0
        self.protocol = 0

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB', buffer1)
        dst_addr = struct.unpack('BBBB', buffer2)
        self.src_ip = ".".join(map(str, src_addr))
        self.dst_ip = ".".join(map(str, dst_addr))

    def get_header_len(self, value):
        result = struct.unpack('B', value)[0]
        self.ip_header_len = (result & 0x0F) * 4

    def get_protocol(self, buffer):
        self.protocol = struct.unpack('B', buffer)[0]

    def get_fragmentation_info(self, id_buffer, frag_buffer):
        self.identification = struct.unpack('>H', id_buffer)[0]
        frag_info = struct.unpack('>H', frag_buffer)[0]
        self.flags = frag_info >> 13
        # Fragment offset is in 8-byte units
        self.frag_offset = (frag_info & 0x1FFF) * 8

class UDP_Header:
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0

    def get_ports(self, buffer):
        self.src_port = struct.unpack('>H', buffer[0:2])[0]
        self.dst_port = struct.unpack('>H', buffer[2:4])[0]

class ICMP_Header:
    def __init__(self):
        self.type = 0
        self.code = 0

    def get_type_and_code(self, buffer):
        self.type, self.code = struct.unpack('BB', buffer[0:2])

class Packet:
    def __init__(self):
        self.IP_header = IP_Header()
        self.UDP_header = None
        self.ICMP_header = None
        self.timestamp = 0.0
        self.is_probe = False
        self.is_error = False
        self.embedded_id = None

def parse_global_header(filename):
    try:
        f = open(filename, "rb")
    except FileNotFoundError:
        sys.exit(1)

    global_hdr = f.read(24)
    if len(global_hdr) < 24: sys.exit(1)

    magic = struct.unpack("<I", global_hdr[:4])[0]
    is_nano = False
    if magic == 0xd4c3b2a1: endian = '<'
    elif magic == 0xa1b2c3d4: endian = '>'
    elif magic == 0x4d3cb2a1: endian = '>'; is_nano = True
    elif magic == 0xa1b23c4d: endian = '<'; is_nano = True
    else: sys.exit(1)

    return endian, f, is_nano

def parse_traceroute_packet(packet_data, ts_sec, ts_frac, ts_multiplier):
    if len(packet_data) < 34: return None
    
    eth_type = struct.unpack(">H", packet_data[12:14])[0]
    if eth_type != 0x0800: return None
    
    p = Packet()
    p.timestamp = ts_sec + (ts_frac * ts_multiplier)
    
    ip_s = 14
    p.IP_header.get_header_len(packet_data[ip_s : ip_s+1])
    p.IP_header.get_IP(packet_data[ip_s+12 : ip_s+16], packet_data[ip_s+16 : ip_s+20])
    p.IP_header.get_protocol(packet_data[ip_s+9 : ip_s+10])
    p.IP_header.get_fragmentation_info(packet_data[ip_s+4 : ip_s+6], packet_data[ip_s+6 : ip_s+8])

    proto = p.IP_header.protocol
    payload_s = ip_s + p.IP_header.ip_header_len

    # Classification based on Tut 10: Logic for Probes vs Errors
    if proto == 17: # UDP Probe
        if len(packet_data) >= payload_s + 4:
            p.UDP_header = UDP_Header()
            p.UDP_header.get_ports(packet_data[payload_s : payload_s+4])
            if 33434 <= p.UDP_header.dst_port <= 33529:
                p.is_probe = True
    elif proto == 1: # ICMP
        if len(packet_data) >= payload_s + 8:
            p.ICMP_header = ICMP_Header()
            p.ICMP_header.get_type_and_code(packet_data[payload_s : payload_s+2])
            
            if p.ICMP_header.type == 8: # Windows Echo Probe
                p.is_probe = True
            elif p.ICMP_header.type in [11, 3, 0]: # Time Exceeded, Unreachable, or Reply
                p.is_error = True
                if p.ICMP_header.type == 0:
                    p.embedded_id = p.IP_header.identification
                else:
                    # Tutorial 10: Match via ID field in the embedded IP header
                    emb_ip_s = payload_s + 8
                    if len(packet_data) >= emb_ip_s + 6:
                        p.embedded_id = struct.unpack(">H", packet_data[emb_ip_s+4 : emb_ip_s+6])[0]
    
    # Also handle fragments that have no transport header (proto 17/1 but offset > 0)
    if not p.is_probe and not p.is_error and p.IP_header.frag_offset > 0:
        p.is_probe = True # Mark as probe for fragmentation tracking

    return p

def analyze_traceroute(packets):
    src, dst = None, None
    routers = []
    protocols = set()
    
    # Datagram tracking for fragments and RTT
    # Key: IP_ID -> {'timestamps': [t1, t2...], 'max_offset': 0}
    datagrams = {} 
    rtt_results = {}
    ult_rtts = []

    for p in packets:
        protocols.add(p.IP_header.protocol)
        if src is None: src = p.IP_header.src_ip

        # Tracking Outgoing Probes (including fragments)
        if p.is_probe and p.IP_header.src_ip == src:
            dst = p.IP_header.dst_ip
            ip_id = p.IP_header.identification
            
            if ip_id not in datagrams:
                datagrams[ip_id] = {'timestamps': [], 'max_offset': 0}
            
            datagrams[ip_id]['timestamps'].append(p.timestamp)
            if p.IP_header.frag_offset > datagrams[ip_id]['max_offset']:
                datagrams[ip_id]['max_offset'] = p.IP_header.frag_offset

        # Tracking Incoming Errors
        elif p.is_error and p.IP_header.dst_ip == src:
            router_ip = p.IP_header.src_ip
            if router_ip != dst and router_ip not in routers:
                routers.append(router_ip)
                rtt_results[router_ip] = []
            
            # Match return packet to probe using the Embedded IP ID (Tutorial 10)
            if p.embedded_id in datagrams:
                for sent_ts in datagrams[p.embedded_id]['timestamps']:
                    rtt_val = (p.timestamp - sent_ts) * 1000
                    if router_ip == dst:
                        ult_rtts.append(rtt_val)
                    else:
                        rtt_results[router_ip].append(rtt_val)

    # Calculate final fragmentation values
    final_fc, final_off = 1, 0
    for did in datagrams:
        count = len(datagrams[did]['timestamps'])
        if count > 1:
            final_fc = count
            final_off = datagrams[did]['max_offset']
            break # Use the first fragmented datagram found

    return src, dst, routers, protocols, final_fc, final_off, rtt_results, ult_rtts

def get_stats(rtt_list):
    if not rtt_list: return 0.0, 0.0
    avg = sum(rtt_list) / len(rtt_list)
    variance = sum((x - avg)**2 for x in rtt_list) / (len(rtt_list) - 1) if len(rtt_list) > 1 else 0.0
    return round(avg, 2), round(math.sqrt(variance), 2)

def generate_output(src, dst, routers, protos, fc, foff, rtts, ult):
    print(f"The IP address of the source node: {src}")
    print(f"The IP address of the destination node: {dst}")
    print("The IP addresses of the intermediate destination nodes:")
    for i, r in enumerate(routers, 1):
        print(f"router {i}: {r}")

    print("The values in the protocol field of IP headers:")
    for p in sorted(list(protos)):
        if p == 1: print("1: ICMP")
        elif p == 17: print("17: UDP")

    print(f"The number of fragments created from the original datagram is {fc}")
    print(f"The offset of the last fragment is: {foff} bytes")

    for r in routers:
        avg, sd = get_stats(rtts[r])
        print(f"The avg RTT between {src} and {r} is: {avg:g} ms, the s.d. is: {sd:g} ms")

    if ult:
        avg, sd = get_stats(ult)
        print(f"The avg RTT between {src} and {dst} is: {avg:g} ms, the s.d. is: {sd:g} ms")

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    
    endian, f_obj, is_nano = parse_global_header(sys.argv[1])
    ts_mult = 1e-9 if is_nano else 1e-6
    
    parsed_packets = []
    while True:
        p_hdr = f_obj.read(16)
        if len(p_hdr) < 16: break
        
        ts_s, ts_f, inc_len, _ = struct.unpack(endian + 'IIII', p_hdr)
        p_data = f_obj.read(inc_len)
        
        p_obj = parse_traceroute_packet(p_data, ts_s, ts_f, ts_mult)
        if p_obj:
            parsed_packets.append(p_obj)
    
    f_obj.close()
    
    results = analyze_traceroute(parsed_packets)
    generate_output(*results)