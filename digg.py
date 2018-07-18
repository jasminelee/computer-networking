import sys 
import socket 

params = sys.argv[1:]
domain_name = params[0]
query_type = params[1]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 8888))
sock.sendto("hello", ("8.8.8.8", 53))
sock.recvfrom(100)

"""
construct a socket
bind to it so we can receive messages back
call send
call receive

open a socket, bind to it, send a request, and see it in wireshark
"""
# def digg(site):


# figure out what the format of the query is. is it a 32 bit address?
# 
