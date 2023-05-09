from pwn import *
from tqdm import trange
from itertools import cycle
from time import sleep
from lib import Packet, PublicKeyCipher


r = remote('cns.csie.org', 12804)
context.arch = 'amd64'

e = 65537
server_n = {}

r.recvuntil(b"server0 is (")
server_n[0] = int(r.recvline().strip().decode().split(", ")[0])
r.recvuntil(b"server1 is (")
server_n[1] = int(r.recvline().strip().decode().split(", ")[0])
r.recvuntil(b"server2 is (")
server_n[2] = int(r.recvline().strip().decode().split(", ")[0])
r.recvuntil(b"Bob is (")
server_n[3] = int(r.recvline().strip().decode().split(", ")[0])

log.info("server0 n: {}\nserver1 n: {}\nserver2 n: {}\n bob n: {}".format(server_n[0], server_n[1], server_n[2], server_n[3]))

r.recvuntil(b"Your public key is (")
my_n = int(r.recvline().strip().decode().split(", ")[0])
r.recvuntil(b"Your private key is (")
my_d = int(r.recvline().strip().decode().split(", ")[1].replace(")", ""))

log.info("My n: {}\nMy d: {}".format(my_n, my_d))

r.recvuntil(b"Wait for 3 seconds to start ...\n")
sleep(3)
while True:
    packet_buffer = []
    next_hop_buffer = []
    while len(next_hop_buffer) < 100:
        message = r.recvline().strip().decode()
        if 'CNS' in message:
            print(message)
            break
        packet = Packet(bytes.fromhex(str(message)))
        next_hop, next_packet = packet.decrypt_server((my_n, my_d))
        
        next_hop_buffer.append(next_hop)
        packet_buffer.append(next_packet)

    for i in trange(len(next_hop_buffer)-1, -1, -1):
        r.sendline("({}, {})".format(next_hop_buffer[i], packet_buffer[i].data.hex()))