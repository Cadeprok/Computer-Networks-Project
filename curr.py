import pyshark
import time
import re

minecraft_file_path = "minecraft_packet_good.pcapng"


packet_info = pyshark.FileCapture(minecraft_file_path)
packet = packet_info[41]
print(packet)
igmp = packet.igmp
print(dir(igmp))
print(igmp.maddr)
'''
print(dir(packet[-2]))
print()
print(packet[-2].length)
'''
'''
eth_layer = packet[0]
ip_layer = packet[1]
print(ip_layer)
print(dir(ip_layer))
print()
print(ip_layer.src)
print(ip_layer.dst)
'''

'''
print(type(packet[-2]))
print(type(packet[-2].layer_name))
print(dir(packet[-2]))
print(packet[-2].tcp_segment)
'''
'''
length = len(packet_info)

packet = packet_info[0]
layer = packet[-1]
print(layer)
layer = packet[-2]
tcp_layer = layer.layer_name
print(tcp_layer)
print(layer.len)
print(dir(tcp_layer))
'''
# print("RECORD CONTENT TYPE: " + tcp_layer)
# print(layer.layer_name)
'''
count = 0
# print(packet_info[0][-1])
packet = str(packet_info[0][-1]).replace(" ", "")
print(packet)
packet = packet.split(":")
print(packet)
cleaned_packet = re.sub(r'[\x00-\x1F\x7F]', '', packet)

# print(cleaned_packet)
'''


