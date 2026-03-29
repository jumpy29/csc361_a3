import struct
import math
import sys

class IP_Header:
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
        self.identification = 0
        self.flags = 0
        self.frag_offset = 0
        self.protocol = 0

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self, length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB', buffer1)
        dst_addr = struct.unpack('BBBB', buffer2)
        s_ip = str(src_addr[0])+"."+str(src_addr[1])+"."+str(src_addr[2])+"."+str(src_addr[3])
        d_ip = str(dst_addr[0])+"."+str(dst_addr[1])+"."+str(dst_addr[2])+"."+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)

    def get_header_len(self, value):
        result = struct.unpack('B', value)[0]
        length = (result & 15) * 4
        self.header_len_set(length)

    def get_total_len(self, buffer):
        length = struct.unpack(">H", buffer)[0]
        self.total_len_set(length)

    def get_protocol(self, buffer):
        self.protocol = struct.unpack('B', buffer)[0]

    #Analyze protocols and fragmentation
    def get_fragmentation_info(self, id_buffer, frag_buffer):
        self.identification = struct.unpack('>H', id_buffer)[0]
        frag_info = struct.unpack('>H', frag_buffer)[0]
        self.flags = frag_info >> 13
        self.frag_offset = (frag_info & 0x1FFF)*8

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
        self.seq_num = 0

    def get_type_and_code(self, buffer):
        self.type, self.code = struct.unpack('BB', buffer[0:2])

    def get_sequence_num(self, buffer):
        self.seq_num = struct.unpack('>H', buffer[0:2])[0]

class packet:
    def __init__(self):
        self.IP_header = IP_Header()
        self.UDP_header = None
        self.ICMP_header = None
        self.timestamp = 0.0
        self.packet_No = 0

        #helper flags for traceroute matching
        self.is_probe = False
        self.is_error = False
        self.embedded_match_key = None

    def timestamp_set(self, buffer1, buffer2, orig_time):
        seconds = struct.unpack("I", buffer1)[0]
        microseconds = struct.unpack("<I", buffer2)[0]
        self.timestamp = round(seconds + microseconds * 0.000001 - orig_time, 6)

    def packet_No_set(self, number):
        self.packet_No = number


# main file

def parse_global_header(filename):
    try:
        f = open(filename, "rb")
    except FileNotFoundError:
        print(f"Error: Could not find {filename}")
        sys.exit(1)

    global_hdr = f.read(24)
    if len(global_hdr)<24:
        print("Error: File is too small.")
        sys.exit(1)

    magic = struct.unpack("<I", global_hdr[:4])[0]
    is_nano = False

    if magic==0xd4c3b2a1:
        endian='<'
    elif magic==0xa1b2c3d4:
        endian='>'
    elif magic==0x4d3cb2a1:
        endian='>'
        is_nano = True
    elif magic==0xa1b23c4d:
        endian='<'
        is_nano = True
    else: 
        print(f"Error: Unknown magic number {hex(magic)}.")
        sys.exit(1)

    return endian, f, is_nano

def parse_traceroute_packet(packet_data, packet_count, ts_sec_bytes, ts_usec_bytes, orig_time):
    # Step 1: How traceroute work. 
    # Because traceroute works by sending probes out and waiting for ICMP errors to come back,
    # classify every packet into one of two buckets: is_probe (the packet your computer sent)
    # or is_error (the ICMP Time Exceeded packet the router returned)
    if len(packet_data)<34:
        return None
    
    eth_type = struct.unpack(">H", packet_data[12:14])[0]
    if eth_type != 0x0800:
        return None
    
    current_packet = packet()
    current_packet.packet_No_set(packet_count)
    current_packet.timestamp_set(ts_sec_bytes, ts_usec_bytes, orig_time)

    ip_start = 14
    current_packet.IP_header.get_header_len(packet_data[ip_start: ip_start+1])
    ip_len = current_packet.IP_header.ip_header_len

    current_packet.IP_header.get_IP(packet_data[ip_start+12: ip_start+16], packet_data[ip_start+16: ip_start+20])
    current_packet.IP_header.get_protocol(packet_data[ip_start+9: ip_start+10])
    current_packet.IP_header.get_fragmentation_info(packet_data[ip_start+4:ip_start+6], packet_data[ip_start+6:ip_start+8])

    protocol = current_packet.IP_header.protocol
    if protocol not in [1, 17]:
        return None
    
    payload_start = ip_start + ip_len

    # UDP processing
    if protocol==17 and len(packet_data)>=payload_start + 4:
        current_packet.UDP_header = UDP_Header()
        current_packet.UDP_header.get_ports(packet_data[payload_start: payload_start+4])

        # filter background UDP noise
        if 33434 <= current_packet.UDP_header.dst_port <= 33529: #linux UDP probe
            current_packet.is_probe = True

    # ICMP processing
    elif protocol==1 and len(packet_data) >= payload_start + 8:
        current_packet.ICMP_header = ICMP_Header()
        current_packet.ICMP_header.get_type_and_code(packet_data[payload_start:payload_start+2])

        icmp_type = current_packet.ICMP_header.type
        if icmp_type==8: #windows echo request probe
            current_packet.ICMP_header.get_sequence_num(packet_data[payload_start+6: payload_start+8])
            current_packet.is_probe = True

        elif icmp_type in [11, 0]: # Time exceeded or echo reply
            current_packet.is_error = True
            orig_ip_start = payload_start + 8

            if len(packet_data) >= orig_ip_start + 20:
                orig_ihl = (packet_data[orig_ip_start] & 0x0F)*4
                orig_protocol = packet_data[orig_ip_start+9]
                orig_payload_start = orig_ip_start + orig_ihl

                if orig_protocol==17 and len(packet_data)>=orig_payload_start+2:
                    current_packet.embedded_match_key = struct.unpack(">H", packet_data[orig_payload_start: orig_payload_start+2])[0] #UDP src port
                elif orig_protocol == 1 and len(packet_data)>=orig_payload_start+8: #Windows ICMP
                    current_packet.embedded_match_key = struct.unpack(">H", packet_data[orig_payload_start+6:orig_payload_start+8])[0] # ICMP seq num

            # Cath Type 0 direct sequence matching (windows trace reaching ultimate destination)
            if icmp_type == 0 and not current_packet.embedded_match_key:
                current_packet.embedded_match_key = struct.unpack(">H", packet_data[payload_start+6: payload_start+8])[0]

            
    return current_packet


def process_packets(file_obj, endian_format, is_nano):
    orig_time = None
    packet_count = 0
    parsed_packets = []
    header_format = endian_format + 'IIII'

    ts_multiplier = 0.000000001 if is_nano else 0.000001

    while True:
        packet_header = file_obj.read(16)
        if len(packet_header)<16:
            break
        
        packet_count += 1

        #unpack header. Second value is either micro or nanoseconds
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(header_format, packet_header)

        absolute_time = ts_sec + (ts_frac * ts_multiplier)

        if orig_time is None: orig_time = absolute_time

        packet_data = file_obj.read(incl_len)

        # parse traceroute packet
        parsed = parse_traceroute_packet(packet_data, packet_count, packet_header[0:4], packet_header[4:8], orig_time)

        if parsed is not None:
            parsed.timestamp = absolute_time
            parsed_packets.append(parsed)

    return parsed_packets

def analyze_traceroute(parsed_packets):
    # Step 2: oop establishes the source node from the very first packet.
    # It then safely appends intermediate routers to a list to preserve the exact order of their hop count
    # (as they appear chronologically in the trace).
    source_node = None
    ultimate_dst = None
    intermediate_nodes = []
    protocols = set()

    frag_count = 0
    last_frag_offset = 0

    probes_sent = {} # Key: match_key -> List of [timestamps]
    rtt_measurements = {}
    ult_rtts = []
    # Step 2: (Node identification)
    for p in parsed_packets:
        protocols.add(p.IP_header.protocol)
        if source_node is None:
            source_node = p.IP_header.src_ip # Step 2: First packet sets the source

        # A. Probes Sent
        if p.is_probe and p.IP_header.src_ip==source_node:
            ultimate_dst = p.IP_header.dst_ip

            # Fragmentation Logic
            # Step 4: Tracking the fragments
            # checks if the "More fragments" flag is 1, or if the offset is greater than 0, to count how many chunks the datagram was split in
            offset = p.IP_header.frag_offset
            mf = p.IP_header.flags & 0x1
            if mf == 1 or p.IP_header.frag_offset > 0: #TODO:changed this
                if offset > last_frag_offset: last_frag_offset = offset
                if offset == 0: frag_count = 0 # reset counter if a new fragmented datagram begins
                frag_count += 1
            elif frag_count == 0:
                frag_count = 1 # 1 if no fragments created (1 total datagram)

            match_key = p.UDP_header.src_port if p.IP_header.protocol==17 else p.ICMP_header.seq_num
            if match_key not in probes_sent: probes_sent[match_key] = []
            probes_sent[match_key].append(p.timestamp)

        # B. Errores Returned
        elif p.is_error and p.IP_header.dst_ip == source_node:
            router_ip = p.IP_header.src_ip
            # Only add if it isn't the final destination and hasn't been added yet
            if router_ip != ultimate_dst and router_ip not in intermediate_nodes:
                intermediate_nodes.append(router_ip) # STep 2: Add itermediate nodes
                rtt_measurements[router_ip] = []
            # Step 3: In analyze_traceroute (Playing matchmaker)
            # Step 5: Calculate RTT
            if p.embedded_match_key and p.embedded_match_key in probes_sent:
                for sent_time in probes_sent[p.embedded_match_key]:
                    # Match found. Move to calculate RTT
                    # RTT = Error Timestamp(T) - Probe Timestamp (t)
                    rtt = round((p.timestamp-sent_time)*1000, 6) # convert to ms
                    # Sort into the correct router's list
                    if router_ip == ultimate_dst:
                        ult_rtts.append(rtt)
                    else:
                        rtt_measurements[router_ip].append(rtt)
                del probes_sent[p.embedded_match_key] # Process fragments once
    
    if frag_count==1 and last_frag_offset==0:
        pass # expects "1" and "0 bytes" for unfragmented traces

    return source_node, ultimate_dst, intermediate_nodes, protocols, frag_count, last_frag_offset, rtt_measurements, ult_rtts

# calculate RTT Averages and Standard Deviation
def calc_stats(rtt_list):
    if not rtt_list: return 0.0, 0.0
    mean = sum(rtt_list) / len(rtt_list)
    variance = sum((x-mean) ** 2 for x in rtt_list) / (len(rtt_list) -1) if len(rtt_list) > 1 else 0.0
    return round(mean, 2), round(math.sqrt(variance), 2)

def generate_output(src, dst, routers, protos, fc, f_off, rtts, ult_rtts):
    print(f"The IP address of the source node: {src}")
    print(f"The IP address of the destination node: {dst}")
    print("The IP addresses of the intermediate destination nodes:")
    for i, router in enumerate(routers, 1):
        print(f"router {i}: {router}")

    print("The values in the protocol field of IP headers:")
    for p in sorted(list(protos)):
        if p==1: print("1: ICMP")
        if p==17: print("17: UDP")

    print(f"The number of fragments created from the original datagram is {fc}")
    print(f"The offset of the last fragment is: {f_off} bytes")

    for router in routers: 
        mean_rtt, sd_rtt = calc_stats(rtts[router])
        mean_str = f"{mean_rtt:g}"
        sd_str = f"{sd_rtt:g}"
        print(f"The avg RTT between {src} and {router} is: {mean_str} ms, the s.d. is: {sd_str} ms")

    if ult_rtts:
        mean_ult, sd_ult = calc_stats(ult_rtts)
        mean_str = f"{mean_ult:g}"
        sd_str = f"{sd_ult:g}"
        print(f"The avg RTT between {src} and {dst} is: {mean_str} ms, the s.d. is: {sd_str} ms")

if __name__=="__main__":
    filename = sys.argv[1]

    endian_format, file_obj, is_nano = parse_global_header(filename)

    if file_obj:
        parsed_packets = process_packets(file_obj, endian_format, is_nano)
        file_obj.close()

        src, dst, routers, protos, fc, f_off, rtts, ult_rtts = analyze_traceroute(parsed_packets)
        generate_output(src, dst, routers, protos, fc, f_off, rtts, ult_rtts)
