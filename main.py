import pyshark

minecraft_file_path = "minecraft_packet_1.pcapng"
map = {}

def main():
    packet_info = pyshark.FileCapture(minecraft_file_path)

    # print(packet_info[0])
    #print(packet_info[0][0])
    # print(packet_info[0][0])
    #packet = dict(packet_info[0][0])
    #print(packet)
    packet = packet_info[0][0]
    print(type(packet))
    # print(packet)

    for packet in packet_info:
        print(packet)

if __name__ == "__main__":
    main()
