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
        # pre-packet header
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

        print captured_length_in_bytes

        # packet data
        while captured_length_in_bytes > 0:
            byte = f.read(1)  # read one number of bytes at a time
            captured_length_in_bytes -= 1
        num_packets += 1
    assert num_packets == 99
