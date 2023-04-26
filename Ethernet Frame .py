# Project2_6388018_6388019_6388071_6388180
import socket
import time
import crcmod
import pyfiglet

# timeout variable can be omitted, if you use specific value in the while condition
timeout = 1   # [seconds]
timeout_start = time.time()

s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
s.bind(("192.168.56.1",0))
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

prev_timestamp = None
# initialize the CRC calculator with the appropriate polynomial
crc_func = crcmod.predefined.Crc('crc-32c')

while time.time() < timeout_start + timeout:
    data, addr = s.recvfrom(10000)
    timestamp = time.time()
    prev_timestamp = timestamp

    #SFD has already been extracted and decoded
    frame_preamble = data[:8]

    # decode the fields in the Frame preamble
    preamble_delimiter = frame_preamble[7]
    preamble_delimiter = frame_preamble[7]

    # extract the Frame preamble from the received data
    frame_preamble = data[:8]

    # decode the fields in the Frame preamble
    preamble_bytes = frame_preamble[:7]
    preamble_delimiter = frame_preamble[7]

    # extract the Ethernet header from the received data
    eth_header = data[:14]

    if eth_header[12:14] == b'\x81\x00':
      vlan_tag = eth_header[14:16]
      eth_type = eth_header[16:18]
    else:
      eth_type = eth_header[12:14]

    # decode the fields in the Ethernet header
    dest_mac = eth_header[:6]
    src_mac = eth_header[6:12]
    eth_type = eth_header[12:14]

    # Determine the upper layer protocol based on the EtherType field value
    if eth_type == b'\x08\x00':
      upper_protocol = 'IPv4'
    elif eth_type == b'\x08\x06':
      upper_protocol = 'ARP'
    elif eth_type == b'\x86\xdd':
      upper_protocol = 'IPv6'
    else:
      upper_protocol = 'Unknown'


   # extract the last 4 bytes for FCS field
    fcs = data[-4:]  
    
  # Assuming a standard IPv4 header length of 20 bytes
    ip_header_length = 20 
    tcp_data_offset = 20

   # extract the payload from the received data
    payload = data[ip_header_length+tcp_data_offset:]

   # extract vlan
    vlan_tag = None

   # extract the frame length
    frame_length = len(data)

   # calculate the CRC on the payload
    crc = crc_func.new(payload).digest()

    # extract the IP header from the received data
    ip_header = data[14:34]

    # decode the fields in the IP header
    ip_header_length = (ip_header[0] & 0xF) * 4
    ip_version = ip_header[0] >> 4
    ip_tos = ip_header[1]
    ip_total_length = ip_header[2:4]
    ip_id = ip_header[4:6]
    ip_flags = ip_header[6] >> 5
    ip_fragment_offset = ((ip_header[6] & 0x1F) << 8) + ip_header[7]
    ip_ttl = ip_header[8]
    ip_protocol = ip_header[9]
    ip_header_checksum = ip_header[10:12]
    ip_source_address = ip_header[12:16]
    ip_destination_address = ip_header[16:20]
    ip_options = ip_header[20:ip_header_length]

    # extract the TCP header from the received data
    tcp_header = data[ip_header_length:ip_header_length+20]

    # decode the fields in the TCP header
    tcp_source_port = tcp_header[0:2]
    tcp_destination_port = tcp_header[2:4]
    tcp_sequence_number = tcp_header[4:8]
    tcp_acknowledgment_number = tcp_header[8:12]
    tcp_data_offset = (tcp_header[12] >> 4) * 4
    tcp_flags = tcp_header[13]
    tcp_window_size = tcp_header[14:16]
    tcp_checksum = tcp_header[16:18]
    tcp_urgent_pointer = tcp_header[18:20]
    tcp_options = tcp_header[20:tcp_data_offset]

    banner = pyfiglet.figlet_format("Ethernet Frame !")
    print(banner)

    print(f'Packet Data: {data.hex()}')
    print('================================================================')
    print('= Ethernet Frame                                               =')
    print('================================================================')
    print('Frame Preamble:')
    # print(f'   Preamble Bytes: {preamble_bytes.__init__()}')
    # print(f'   Preamble Delimiter: {preamble_delimiter.__int__()}')
    print(f'Start Frame Delimiter (SFD): {preamble_delimiter.__int__()}')
    print('Ethernet Header:')
    print(f'  Destination MAC: {dest_mac.hex()}')
    print(f'  Source MAC: {src_mac.hex()}')
    print(f'  Ethernet Type: {eth_type.hex()} ({upper_protocol})')
    #print(f'  Frame Length: {frame_length}')
    # if prev_timestamp is not None:
    #     ipg = timestamp - prev_timestamp
    #     print(f'  interpacket gap (IPG): {ipg}')
    # prev_timestamp = timestamp    
    # if vlan_tag is not None:
    #  print(f'  VLAN Tag: {vlan_tag.hex()}')  

    print(f'Payload: {payload[ip_header_length:]}')
    print(f'Frame check sequence (FCS): {fcs.hex()}')
    print(f'CRC: {crc.hex()}')
    
    print('================================================================')
    print('|| IP Header:                                                  ||')
    print('================================================================')
    print(f'  Version: {ip_version}')
    print(f'  Header Length: {ip_header_length}')
    print(f'  TOS: {ip_tos}')
    print(f'  Total Length: {int.from_bytes(ip_total_length, byteorder="big")}')
    print(f'  Identification: {int.from_bytes(ip_id, byteorder="big")}')
    print(f'  Flags: {ip_flags}')
    print(f'  Fragment Offset: {ip_fragment_offset}')
    print(f'  TTL: {ip_ttl}')
    print(f'  Protocol: {ip_protocol}')
    print(f'  Header Checksum: {ip_header_checksum}')
    print(f'  Source Address: {ip_source_address}')
    print(f'  Destination Address: {ip_destination_address}')
    print('================================================================')
    print('|| TCP Header:                                                ||')
    print('================================================================')
    print(f'  TCP Source Port: {int.from_bytes(tcp_source_port, byteorder="big")}')
    print(f'  TCP Destination Port: {int.from_bytes(tcp_destination_port, byteorder="big")}')
    print(f'  TCP Sequence Number: {int.from_bytes(tcp_sequence_number, byteorder="big")}')
    print(f'  TCP Acknowledgment Number: {int.from_bytes(tcp_acknowledgment_number, byteorder="big")}')
    print(f'  TCP Data Offset: {tcp_data_offset}')
    print(f'  TCP Flags: {tcp_flags}')
    print(f'  TCP Window Size: {int.from_bytes(tcp_window_size, byteorder="big")}')
    print(f'  TCP Checksum: {int.from_bytes(tcp_checksum, byteorder="big")}')
    print(f'  TCP Urgent Pointer: {int.from_bytes(tcp_urgent_pointer, byteorder="big")}')
    print(f'  TCP Options: {tcp_options.hex()}')
    print('================================================================')

    
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
s.close()