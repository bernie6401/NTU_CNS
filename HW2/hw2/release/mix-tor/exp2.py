from pwn import *
from tqdm import trange
from itertools import cycle
from time import sleep
from lib import Packet, PublicKeyCipher


r = remote('cns.csie.org', 12805)
context.arch = 'amd64'

e = 65537
server_n = {}
message = 'Give me flag, now!'

r.recvuntil(b"server0 is (")
server_n[0] = int(r.recvline().strip().decode().split(", ")[0])
r.recvuntil(b"server1 is (")
server_n[1] = int(r.recvline().strip().decode().split(", ")[0])
r.recvuntil(b"server2 is (")
server_n[2] = int(r.recvline().strip().decode().split(", ")[0])
r.recvuntil(b"Bob is (")
server_n[3] = int(r.recvline().strip().decode().split(", ")[0])

log.info("server0 n: {}\nserver1 n: {}\nserver2 n: {}\n bob n: {}".format(server_n[0], server_n[1], server_n[2], server_n[3]))

r.recvuntil(b"The route of the packet should be [")
route = r.recvline().strip().decode().split("]")[0].split(', ')
log.info("The route sequence is: {}".format(route))


'''Add next hop'''
packet = Packet(bytes.fromhex(message))
for i in range(len(route) - 1):
    next_hop, next_packet = packet.add_next_hop(message, (server_n[i], e))
    assert next_hop == route[i+1]
    packet = next_packet
message = packet.encrypt_client(sk[3])
assert message == b'Give me flag, now!'


'''Testing'''
# for i in range(len(route) - 1):
#     next_hop, next_packet = packet.decrypt_server(sk[route[i]])
#     assert next_hop == route[i+1]
#     packet = next_packet
# message = packet.decrypt_client(sk[3])
# assert message == b'Give me flag, now!'

r.interactive()