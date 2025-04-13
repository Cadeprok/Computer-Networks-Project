import pyshark
import math

minecraft_file_path = "minecraft_packets/minecraft_packet_good.pcapng"
network_file_path = "networkpackets/network_packet_good.pcapng"
# Hashmap of all protocols: key = protocol, value = amount
minecraft_protocol_map = {}
network_protocol_map = {}
# Counts of packets
total_count, minecraft_count, network_count = 0,0,0
# Max and mins of tcp and udp segments for minecraft and overall network
max_mc_tcp_segment_length, min_mc_tcp_segment_length, max_net_tcp_segment_length, min_net_tcp_segment_length = float('-inf'), float('inf'), float('-inf'), float('inf')
max_mc_udp_segment_length, min_mc_udp_segment_length, max_net_udp_segment_length, min_net_udp_segment_length = float('-inf'),float('inf'),float('-inf'),float('inf')
# Total packet lengths of tcp and udp transmitted through minecraft and total network
total_mc_tcp_seg, total_net_tcp_seg = 0,0
total_mc_udp_seg, total_net_udp_seg = 0,0
# All unique ports and ips active through all minecraft and overall network packets
minecraft_ip_list, minecraft_port_list = set(), set()
network_ip_list, network_port_list = set(), set()
# Hashmaps for amount of tcp segments and tcp packet lengths across time for network and minecraft 
tcp_seg_num_against_time_mc,tcp_seg_num_against_time_network = {}, {}
tcg_seg_amount_against_time_mc,tcg_seg_amount_against_time_network = {}, {}

def format_num(num:int) -> str:
    pass

def process_minecraft_packet(packet_info) -> None:
    global total_count, minecraft_count
    global max_mc_tcp_segment_length, min_mc_tcp_segment_length
    global minecraft_ip_list, minecraft_port_list
    global max_mc_udp_segment_length, min_mc_udp_segment_length
    global total_mc_tcp_seg, total_mc_udp_seg
    global minecraft_protocol_map
    global tcg_seg_amount_against_time_mc, tcp_seg_num_against_time_mc

    for packet in packet_info:
        for layer in packet:
            try:
                # If layer has garbage values, ignore...
                if layer.layer_name in ["DATA", 'data-text-lines']:
                    continue
                if str(layer.layer_name) == "tls":
                    tls_layer = packet.tls
                    sub = "Application Data Protocol"
                    # Check if record exists, if it doesnt, then its None
                    record = None
                    # Try, except is needed because if tls_layer.record does not exist, an error occurs, forcing the entire iteration to be dropped
                    # even when additional information can be proccessed, the nested try, except prevents this.
                    try:
                        record = tls_layer.record
                    except:
                        record = None
                    
                    # Check for correct record type
                    if record != None and sub in str(tls_layer.record.showname_value):
                        # Break down record type for temporary application data protocol
                        application_data_protocol = str(tls_layer.record.showname_value.split(": ")[-1])

                        # If application data protocol is http, add http to overall map in correct format
                        if application_data_protocol in ['HyperText Transfer Protocol 2', 'Hypertext Transfer Protocol']:
                            minecraft_protocol_map['http'] = minecraft_protocol_map.get('http', 0) + 1
                        # Otherwise, still add it with ambiguous format
                        else:
                            minecraft_protocol_map[str(application_data_protocol)] = minecraft_protocol_map.get(str(application_data_protocol), 0) + 1

                if str(layer.layer_name) == "tcp":
                    tcp_layer = layer

                    # Get segment length, None if it doesnt exist
                    packet_length = int(tcp_layer.len) if tcp_layer.len else None

                    # Check segment length against min and max length
                    if packet_length != None and packet_length > max_mc_tcp_segment_length:
                        max_mc_tcp_segment_length = packet_length
                    if packet_length != None and packet_length < min_mc_tcp_segment_length and packet_length != 0:
                        min_mc_tcp_segment_length = packet_length
                    
                    # Breakdown specific tcp segments ports
                    minecraft_port_list.add(int(layer.port))
                    minecraft_port_list.add(int(layer.dstport))

                    # Add packet length to total TCP packet length for minecraft
                    total_mc_tcp_seg += int(packet_length)

                    # Add packet length and packet number to hashmap for graph
                    tcp_seg_num_against_time_mc[str((minecraft_count + 1) // 250)] = tcp_seg_num_against_time_mc.get(str((minecraft_count + 1) // 250), 0) + 1
                    tcg_seg_amount_against_time_mc[str((minecraft_count + 1) // 250)] = tcg_seg_amount_against_time_mc.get(str((minecraft_count + 1) // 250), 0) + int(packet_length)

                if str(layer.layer_name) == "ip":
                    # Break down IPs in specific layer info
                    minecraft_ip_list.add(layer.src)
                    minecraft_ip_list.add(layer.dst)

                if str(layer.layer_name) == "udp":
                    # Break down IPs 
                    minecraft_port_list.add(int(layer.srcport))
                    minecraft_port_list.add(int(layer.dstport))
                    # Make sure packet segment is a number
                    packet_length = int(layer.length)
                    
                    # Compare packet length to min and max udp segment lengths
                    if packet_length > max_mc_udp_segment_length:
                        max_mc_udp_segment_length = packet_length
                    if packet_length < min_mc_udp_segment_length and packet_length != 0:
                        min_mc_udp_segment_length = packet_length

                    # Add current packet length to total udp segment 
                    total_mc_udp_seg += packet_length       

                if str(layer.layer_name) == "ipv6":
                    # Breakdown IP address for this layer
                    minecraft_ip_list.add(layer.src)

                if str(layer.layer_name) == "igmp":
                    # Breakdown IP address for this layer
                    minecraft_ip_list.add(layer.maddr)
                
                # No matter what, add protocol to overall protocol map
                minecraft_protocol_map[str(layer.layer_name)] = minecraft_protocol_map.get(str(layer.layer_name), 0) + 1

            except:
                # If an error occurs while processing
                print("An error occured, skipping")
        
        #  Add one to counts after iteration
        total_count += 1
        minecraft_count += 1


def process_total_network_packet(packet_info) -> None:
    global total_count, network_count
    global max_net_tcp_segment_length, min_net_tcp_segment_length
    global max_net_udp_segment_length, min_net_udp_segment_length
    global network_ip_list, network_port_list
    global network_protocol_map
    global total_net_tcp_seg, total_net_udp_seg
    global tcp_seg_num_against_time_network, tcg_seg_amount_against_time_network
    for packet in packet_info:
        for layer in packet:
            try:
                # If layer has garbage values, ignore...
                if layer.layer_name in ["DATA", 'data-text-lines']:
                    continue
                if str(layer.layer_name) == "tls":
                    tls_layer = packet.tls
                    sub = "Application Data Protocol"
                    # Check if record exists, if it doesnt, then its None
                    record = None
                    # Try, except is needed because if tls_layer.record does not exist, an error occurs, forcing the entire iteration to be dropped
                    # even when additional information can be proccessed, the nested try, except prevents this.
                    try:
                        record = tls_layer.record
                    except:
                        record = None
                    # Check for correct record type
                    if record != None and sub in str(tls_layer.record.showname_value):
                        # Break down record type for temporary application data protocol
                        application_data_protocol = str(tls_layer.record.showname_value.split(": ")[-1])
                        # If application data protocol is http, add http to overall map in correct format
                        if application_data_protocol in ['HyperText Transfer Protocol 2', 'Hypertext Transfer Protocol']:
                            network_protocol_map['http'] = network_protocol_map.get('http', 0) + 1
                        # Otherwise, still add it with ambiguous format
                        else:
                            network_protocol_map[str(application_data_protocol)] = network_protocol_map.get(str(application_data_protocol), 0) + 1

                if str(layer.layer_name) == "tcp":
                    tcp_layer = layer
                    # Get segment length, None if it doesnt exist
                    packet_length = int(tcp_layer.len) if tcp_layer.len else None

                    # Check segment length against min and max length
                    if packet_length != None and packet_length > max_net_tcp_segment_length:
                        max_net_tcp_segment_length = packet_length
                    if packet_length != None and packet_length < min_net_tcp_segment_length and packet_length != 0:
                        min_net_tcp_segment_length = packet_length

                    # Breakdown specific tcp segments ports
                    network_port_list.add(int(layer.port))
                    network_port_list.add(int(layer.dstport))

                    # Add packet length to total TCP packet length for network
                    total_net_tcp_seg += packet_length

                    # Add packet length and packet number to hashmap for graph
                    tcp_seg_num_against_time_network[str((network_count + 1) // 250)] = tcp_seg_num_against_time_network.get(str((network_count + 1) // 250), 0) + 1
                    tcg_seg_amount_against_time_network[str((network_count + 1) // 250)] = tcg_seg_amount_against_time_network.get(str((network_count + 1) // 250), 0) + int(packet_length)

                if str(layer.layer_name) == "ip":
                    # Break down IPs in specific layer info
                    network_ip_list.add(layer.src)
                    network_ip_list.add(layer.dst)

                if str(layer.layer_name) == "udp":
                    # Break down IPs
                    network_port_list.add(int(layer.srcport))
                    network_port_list.add(int(layer.dstport))
                    # Make sure packet segment is a number
                    packet_length = int(layer.length)

                    # Compare packet length to min and max udp segment lengths
                    if packet_length > max_net_udp_segment_length:
                        max_net_udp_segment_length = packet_length
                    if packet_length < min_net_udp_segment_length and packet_length != 0:
                        min_net_udp_segment_length = packet_length

                    # Add current packet length to total udp segment      
                    total_net_udp_seg += packet_length

                if str(layer.layer_name) == "ipv6":
                    # Breakdown IP address for this layer
                    network_ip_list.add(layer.src)

                if str(layer.layer_name) == "igmp":
                    # Breakdown IP address for this layer
                    network_ip_list.add(layer.maddr)
                
                # No matter what, add protocol to overall protocol map
                network_protocol_map[str(layer.layer_name)] = network_protocol_map.get(str(layer.layer_name), 0) + 1

            except:
                # If an error occurs while processing
                print("An error occured, skipping")

        #  Add one to counts after iteration
        total_count += 1
        network_count += 1



def main() -> None:

    # Covert file to readible python packet
    minecraft_packet_info = pyshark.FileCapture(minecraft_file_path)
    network_packet_info = pyshark.FileCapture(network_file_path)

    # Process packets
    process_minecraft_packet(minecraft_packet_info)
    process_total_network_packet(network_packet_info)
    
    
if __name__ == "__main__":
    main()
