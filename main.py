import pyshark
import math

minecraft_file_path = "minecraft_packet_good.pcapng"
network_file_path = "network_packet_good.pcapng"
minecraft_protocol_map = {}
network_protocol_map = {}
total_count, minecraft_count, network_count = 0,0,0

max_mc_tcp_segment_length, min_mc_tcp_segment_length, max_net_tcp_segment_length, min_net_tcp_segment_length = float('-inf'), 99999, float('-inf'), 99999
max_mc_udp_segment_length, min_mc_udp_segment_length, max_net_udp_segment_length, min_net_udp_segment_length = 0,99999999999999,0,999999999
total_mc_tcp_seg, total_net_tcp_seg = 0,0
total_mc_udp_seg, total_net_udp_seg = 0,0
minecraft_ip_list = set()
minecraft_port_list = set()
network_ip_list = set()
network_port_list = set()


def format_num(num:int) -> str:
    pass



def process_minecraft_packet(packet_info) -> None:
    global total_count
    global max_mc_tcp_segment_length
    global min_mc_tcp_segment_length
    global minecraft_ip_list
    global minecraft_port_list
    global minecraft_count
    global max_mc_udp_segment_length
    global min_mc_udp_segment_length
    global total_mc_tcp_seg, total_mc_udp_seg
    global minecraft_protocol_map
    for packet in packet_info:
        for layer in packet:
            try:
                if layer.layer_name in ["DATA", 'data-text-lines']:
                    continue
                if str(layer.layer_name) == "tls":

                    minecraft_protocol_map[str(layer.layer_name)] = minecraft_protocol_map.get(str(layer.layer_name), 0) + 1
                    tls_layer = packet.tls

                    sub = "Application Data Protocol"
                    record = None
                    try:
                        record = tls_layer.record
                    except:
                        record = None
                    
                    if record != None and sub in str(tls_layer.record.showname_value):
                        application_data_protocol = str(tls_layer.record.showname_value.split(": ")[-1])

                        if application_data_protocol in ['HyperText Transfer Protocol 2', 'Hypertext Transfer Protocol']:
                            minecraft_protocol_map['http'] = minecraft_protocol_map.get('http', 0) + 1
                        else:
                            minecraft_protocol_map[str(application_data_protocol)] = minecraft_protocol_map.get(str(application_data_protocol), 0) + 1

                if str(layer.layer_name) == "tcp":
                    tcp_layer = layer
                    packet_length = int(tcp_layer.len) if tcp_layer.len else None

                    if packet_length != None and packet_length > max_mc_tcp_segment_length:
                        max_mc_tcp_segment_length = packet_length
                    if packet_length != None and packet_length < min_mc_tcp_segment_length and packet_length != 0:
                        min_mc_tcp_segment_length = packet_length
                    
                    minecraft_port_list.add(int(layer.port))
                    minecraft_port_list.add(int(layer.dstport))
                    total_mc_tcp_seg += packet_length

                if str(layer.layer_name) == "ip":
                    minecraft_ip_list.add(layer.src)
                    minecraft_ip_list.add(layer.dst)

                if str(layer.layer_name) == "udp":
                    minecraft_port_list.add(int(layer.srcport))
                    minecraft_port_list.add(int(layer.dstport))
                    packet_length = int(layer.length)

                    if packet_length > max_mc_udp_segment_length:
                        max_mc_udp_segment_length = packet_length
                    if packet_length < min_mc_udp_segment_length and packet_length != 0:
                        min_mc_udp_segment_length = packet_length

                    total_mc_udp_seg += packet_length       

                if str(layer.layer_name) == "ipv6":
                    minecraft_ip_list.add(layer.src)

                if str(layer.layer_name) == "igmp":
                    minecraft_ip_list.add(layer.maddr)
                
                minecraft_protocol_map[str(layer.layer_name)] = minecraft_protocol_map.get(str(layer.layer_name), 0) + 1

            except:
                print("An error occured, skipping")
    
        total_count = total_count + 1
        minecraft_count += 1


def process_total_network_packet(packet_info) -> None:
    global total_count, network_count
    global max_net_tcp_segment_length, min_net_tcp_segment_length, total_mc_tcp_seg
    global max_net_udp_segment_length, min_net_udp_segment_length
    global network_ip_list, network_port_list
    global network_protocol_map
    global total_net_tcp_seg, total_net_udp_seg
    
    for packet in packet_info:
        for layer in packet:
            try:
                if layer.layer_name in ["DATA", 'data-text-lines']:
                    continue
                if str(layer.layer_name) == "tls":

                    network_protocol_map[str(layer.layer_name)] = network_protocol_map.get(str(layer.layer_name), 0) + 1
                    tls_layer = packet.tls

                    sub = "Application Data Protocol"
                    record = None
                    try:
                        record = tls_layer.record
                    except:
                        record = None
                    
                    if record != None and sub in str(tls_layer.record.showname_value):
                        application_data_protocol = str(tls_layer.record.showname_value.split(": ")[-1])

                        if application_data_protocol in ['HyperText Transfer Protocol 2', 'Hypertext Transfer Protocol']:
                            network_protocol_map['http'] = network_protocol_map.get('http', 0) + 1
                        else:
                            network_protocol_map[str(application_data_protocol)] = network_protocol_map.get(str(application_data_protocol), 0) + 1

                if str(layer.layer_name) == "tcp":
                    tcp_layer = layer
                    packet_length = int(tcp_layer.len) if tcp_layer.len else None

                    if packet_length != None and packet_length > max_net_tcp_segment_length:
                        max_net_tcp_segment_length = packet_length
                    if packet_length != None and packet_length < min_net_tcp_segment_length and packet_length != 0:
                        min_net_tcp_segment_length = packet_length
                    
                    network_port_list.add(int(layer.port))
                    network_port_list.add(int(layer.dstport))
                    total_net_tcp_seg += packet_length


                if str(layer.layer_name) == "ip":
                    network_ip_list.add(layer.src)
                    network_ip_list.add(layer.dst)

                if str(layer.layer_name) == "udp":
                    network_port_list.add(int(layer.srcport))
                    network_port_list.add(int(layer.dstport))
                    packet_length = int(layer.length)

                    if packet_length > max_net_udp_segment_length:
                        max_net_udp_segment_length = packet_length
                    if packet_length < min_net_udp_segment_length and packet_length != 0:
                        min_net_udp_segment_length = packet_length
                                        
                    total_net_udp_seg += packet_length

                if str(layer.layer_name) == "ipv6":
                    network_ip_list.add(layer.src)

                if str(layer.layer_name) == "igmp":
                    network_ip_list.add(layer.maddr)
                
                network_protocol_map[str(layer.layer_name)] = network_protocol_map.get(str(layer.layer_name), 0) + 1

            except:
                print("An error occured, skipping")
    
        total_count = total_count + 1
        network_count += 1


def main() -> None:
    global minecraft_file_path, network_file_path
    global network_port_list
    minecraft_packet_info = pyshark.FileCapture(minecraft_file_path)
    network_packet_info = pyshark.FileCapture(network_file_path)

    process_minecraft_packet(minecraft_packet_info)
    process_total_network_packet(network_packet_info)

    '''
    total_count, minecraft_count, network_count = 0,0,0

    max_mc_tcp_segment_length, min_mc_tcp_segment_length, max_net_tcp_segment_length, min_net_tcp_segment_length = float('-inf'), float('inf'), float('-inf'), float('inf')
    max_mc_udp_segment_length, min_mc_udp_segment_length, max_net_udp_segment_length, min_net_udp_segment_length = 0,99999999999999,0,999999999
    total_mc_tcp_seg, total_net_tcp_seg = 0,0
    minecraft_ip_list = set()
    minecraft_port_list = set()
    network_ip_list = set()
    network_port_list = set()
    '''
    print(total_count)
    print(minecraft_count)
    print(network_count)
    print(max_mc_tcp_segment_length)
    print(min_mc_tcp_segment_length)
    print(max_net_tcp_segment_length)
    print(min_net_tcp_segment_length)
    print(max_mc_udp_segment_length)
    print(min_mc_udp_segment_length)
    print(max_net_udp_segment_length)
    print(min_net_udp_segment_length)
    print(total_mc_tcp_seg)
    print(total_net_tcp_seg)

    print("\n")

    print(minecraft_protocol_map)
    print(network_protocol_map)




    
if __name__ == "__main__":
    main()
