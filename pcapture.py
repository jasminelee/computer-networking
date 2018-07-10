import binascii
import struct

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
    link_layer_bytes = f.read(4)

    byte = link_layer_bytes
    num_packets = 0
    while byte != "":
        byte = f.read(4)  # timestamp
        byte = f.read(4)  # timestamp in ms
        packet_length_bytes = f.read(4)  # num_bytes
        packet_length_in_bytes = struct.unpack(
            "<I", packet_length_bytes)  # number of bytes in packet
        packet_length_in_bytes = packet_length_in_bytes[0]

        while packet_length_in_bytes > 0:
            f.read(1)  # read one number of bytes at a time
            packet_length_in_bytes -= 1
        # Un-truncated length of the packet data
        byte = f.read(4)
        num_packets += 1

    print "num_packets: {}".format(num_packets)
    # magic_number = struct.unpack('<I', byte)
    # print magic_number

    # while byte != "":
    #     # Do stuff with byte.
    #     byte = f.read(1)
    #     print binascii.hexlify(byte)
