import binascii
import struct

"""
https://my.bradfieldcs.com/networking/2018-07/overview-exercise/
"""

with open("net.cap", "rb") as f:

    # per-file header according to https://www.tcpdump.org/manpages/pcap-savefile.5.txt
    magic_number_bytes = f.read(4)
    magic_number = binascii.hexlify(magic_number_bytes)
    print "Magic number: {}".format(magic_number)

    major_version_bytes = f.read(2)
    major_version = struct.unpack('<H', major_version_bytes)[0]
    assert major_version == 2

    minor_version = struct.unpack('<H', f.read(2))[0]
    assert minor_version == 4

    timezone_offset_bytes = f.read(4)
    assert struct.unpack("<I", timezone_offset_bytes)[0] == 0

    timezone_accuracy = struct.unpack('<I', f.read(4))[0]
    assert timezone_accuracy == 0

    snapshot_length = struct.unpack('<I', f.read(4))[0]
    print "Snapshot length: {}".format(snapshot_length)

    byte = struct.unpack('<I', f.read(4))[0]  # link layer header type
    assert byte == 1  # ethernet type

    num_packets = 0
    while byte != "":
        # per-packet header
        byte = f.read(4)  # timestamp
        if byte == "":
            break
        # timestamp in ms
        timestamp_ms = f.read(4)
        # number of bytes in packet
        captured_length_in_bytes = struct.unpack("<I", f.read(4))[0]
        # Un-truncated length of the packet data
        untruncated_length_in_bytes = struct.unpack("<I", f.read(4))[0]

        assert captured_length_in_bytes == untruncated_length_in_bytes

        # # parsing the layer 2 ethernet frame

        dest, source, ether_type = struct.unpack('<6s6sH', f.read(14))
        # dest1, dest2, source1, source2, ether_type = struct.unpack(
        #     '<LHLHH', f.read(14))
        # print "dest: {}, source: {}".format(dest1, source1)
        assert ether_type == 8

        # unpacking takes binary data and makes it human readable
        # IP Header. go into payload and get ip versions and IP header lengths
        version_field_header_length = struct.unpack("B", f.read(1))[0]
        version_field = version_field_header_length >> 4
        IP_header_length = version_field_header_length & 0x0f
        assert version_field == 4
        # print "IP_header_length: {}".format(IP_header_length)

        differentiated_services = f.read(1)
        total_length_bytes = f.read(2)
        # length of datagram payload
        total_length = struct.unpack("<H", total_length_bytes)[
            0]
        # print "total length: {}".format(total_length)
        id_field = f.read(2)
        offset_field = f.read(2)
        ttl = f.read(1)
        protocol_field_bytes = f.read(1)
        protocol_field = struct.unpack("<B", protocol_field_bytes)[0]
        assert protocol_field == 6  # indicates tcp

        header_checksum = f.read(2)
        source_IP = struct.unpack("<I", f.read(4))[0]
        destination_IP = struct.unpack("<I", f.read(4))[0]
        # should be the same two IPS
        # print "Source IP: {}, destination IP: {}".format(source_IP, destination_IP)

        # parsing TCP headers
        source_port = struct.unpack("<H", f.read(2))[0]
        destination_port = struct.unpack("<H", f.read(2))[0]
        sequence_number = struct.unpack("<I", f.read(4))[0]
        print sequence_number

        captured_length_in_bytes -= 42

        # print "Number in bytes in the rest of the packet
        # {}".format(captured_length_in_bytes)
        while captured_length_in_bytes > 0:
            captured_length_in_bytes -= 1
            f.read(1)
        num_packets += 1
    assert num_packets == 99
