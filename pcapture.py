import binascii
import struct

"""
https://my.bradfieldcs.com/networking/2018-07/overview-exercise/
"""

with open("net.cap", "rb") as f:
    magic_number_bytes = f.read(4)
    magic_number = binascii.hexlify(magic_number_bytes)
    print "magic number: {}".format(magic_number)

    major_version_bytes = f.read(2)
    major_version = struct.unpack('<H', major_version_bytes)
    print "major_version: {}".format(major_version)

    minor_version_bytes = f.read(2)
    timezone_offset_bytes = f.read(4)
    timezone_accuracy_bytes = f.read(4)
    snapshot_length_bytes = f.read(4)
    byte = f.read(4)  # link-layer

    num_packets = 0
    while byte != "":
        # per-packet header
        byte = f.read(4)  # timestamp
        if byte == "":
            break
        byte = f.read(4)  # timestamp in ms
        byte = f.read(4)  # length of captured packet data
        captured_length_in_bytes = struct.unpack(
            "<I", byte)  # number of bytes in packet
        captured_length_in_bytes = captured_length_in_bytes[0]
        byte = f.read(4)  # Un-truncated length of the packet data
        untruncated_length_in_bytes = struct.unpack("<I", byte)
        untruncated_length_in_bytes = untruncated_length_in_bytes[0]

        if captured_length_in_bytes != untruncated_length_in_bytes:
            print "Packet was truncated"

        # # parsing the layer 2 ethernet frame

        destination_mac_address_bytes1 = f.read(4)
        destination_mac_address1 = struct.unpack(
            "<I", destination_mac_address_bytes1)[0]
        destination_mac_address_bytes2 = f.read(2)
        destination_mac_address2 = struct.unpack(
            "<H", destination_mac_address_bytes2)[0]
        # print "MAC destination: ", destination_mac_address1, destination_mac_address2

        source_mac_address_bytes1 = f.read(4)
        source_mac_address1 = struct.unpack(
            "<I", source_mac_address_bytes1)[0]

        source_mac_address_bytes2 = f.read(2)
        source_mac_address2 = struct.unpack(
            "<H", source_mac_address_bytes2)[0]
        # print "MAC source: ", source_mac_address1, source_mac_address2

        ether_type = f.read(2)

        # IP Header. go into payload and get ip versions and IP header lengths
        version_field_header_length_bytes = f.read(1)
        version_field_header_length = struct.unpack(
            "<B", version_field_header_length_bytes)[0]
        version_field_header_length = str(version_field_header_length)
        # print version_field_header_length
        version_field = version_field_header_length[:len(
            version_field_header_length) / 2]
        print "version field:" + version_field
        # assert version_field == "4" or version_field == "6"

        IP_header_length = version_field_header_length[
            len(version_field_header_length) / 2:]
        IP_header_length = int(IP_header_length) % 0xff
        IP_header_length *= 4
        print "IP_header_length: {}".format(IP_header_length)

        differentiated_services = f.read(1)
        total_length_bytes = f.read(2)
        # length of datagram payload
        total_length = struct.unpack("<H", total_length_bytes)[
            0]
        id_field = f.read(2)
        offset_field = f.read(2)
        ttl = f.read(1)
        protocol_field_bytes = f.read(1)
        protocol_field = struct.unpack("<B", protocol_field_bytes)[0]
        # print "protocol", protocol_field
        # assert protocol_field == 6

        header_checksum = f.read(2)
        source_IP = struct.unpack("<I", f.read(4))[0]
        destination_IP = struct.unpack("<I", f.read(4))[0]

        # should be the same two IPS
        # print "Source IP: {}, destination IP: {}".format(source_IP, destination_IP)
        captured_length_in_bytes -= 34

        # if IP_header_length > 5:

        # print "Number in bytes in the rest of the packet
        # {}".format(captured_length_in_bytes)
        while captured_length_in_bytes > 0:
            captured_length_in_bytes -= 1
            f.read(1)
        num_packets += 1
    assert num_packets == 99
