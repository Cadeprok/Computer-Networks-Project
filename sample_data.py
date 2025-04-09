'''

pip install matplotlib

cd into directory
python3 sample_data.py
'''

import matplotlib
total_count = 22525
minecraft_count = 9251
network_count = 13274
max_mc_tcp_segment_length = 1460
min_mc_tcp_segment_length = 0
max_net_tcp_segment_length = 1250
min_net_tcp_segment_length = 0
max_mc_udp_segment_length = 1258
min_mc_udp_segment_length = 31
max_net_udp_segment_length = 1288
min_net_udp_segment_length = 29
total_mc_tcp_seg = 2716335
total_net_tcp_seg = 1995534

minecraft_protocol_map = {'eth': 9251, 'ip': 9239, 'udp': 203, 'dns': 65, 'tcp': 9015, 'tls': 1066, 'http': 453, 'igmp': 26, 'png': 36, 
                          'arp': 7, 'mdns': 9, 'ipv6': 5, 'quic': 43, 'ssdp': 1, 'hipercontracer': 3}
network_protocol_map = {'eth': 13274, 'ip': 13168, 'udp': 8598, 'dns': 319, 'tcp': 4570, 'tls': 3052, 'http': 1063, 'ipv6': 106, 'icmpv6': 106, 'quic': 7623}


minecraft_ip_num = 12
minecraft_port_num = 22
network_ip_num = 42
network_port_num = 50

'''
General information will get printed out into the terminal
^^ Numbers will be formated (ex: 8235600 --> 8.23m, i will make the function for this)

Set of pie graphs for minecraft_protocol_map and network_protocol_map
Set of pie graphs for minecraft_protocol_map and network_protocol_map without the common protocols (eth, ip, tcp, tls)



'''