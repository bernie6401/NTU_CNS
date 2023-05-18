from pwn import *
from tqdm import trange
from itertools import cycle
from time import sleep
from lib import Packet, PublicKeyCipher
# from factordb.factordb import FactorDB


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
r.recvline()


'''Compute Private Key'''
# p, q = {}, {}
# for i in range(4):
#     f = FactorDB(server_n[i])
#     response = f.connect()
#     tmp = f.get_factor_list()


packet = b'Give me flag, now!'
for i in trange(len(route)):
    send_to = route[-1-i].encode()
    pk = (server_n[int(route[-1-i])], e)
    packet = Packet.create(packet, send_to, pk, i)

    '''test part'''
    # if i >= 0:
    #     sk = input()
    #     tmp = Packet(bytes.fromhex(packet))
    #     if i == 0:
    #         message = tmp.decrypt_client((server_n[int(route[-1-i])], int(sk)))
    #     else:
    #         next_hop, next_packet = tmp.decrypt_server((server_n[int(route[-1-i])], int(sk)))
    #     # next_hop, next_packet = tmp.decrypt_server((server_n[int(route[-1-i])], int(sk)))
    #     # assert next_hop == route[-1-i]
    #     # tmp = next_packet
print(len(packet))
r.sendlineafter(b'> ', packet)

r.interactive()