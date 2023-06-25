import socket

query = bytes.fromhex('82980100000100000000000003777777076578616d706c6503636f6d0000010001')
print(len(query))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(query, ("8.8.8.8", 53))
response, _ = sock.recvfrom(1024)
