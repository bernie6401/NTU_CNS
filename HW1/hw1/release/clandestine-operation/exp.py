from pwn import *
from tqdm import trange

r = remote('cns.csie.org', 44399)
context.arch = 'amd64'
tmp_ID = ID = b'70309f98653e87df804263d5a0348f115c36bc7c2cddfe02ffd44528083635404815ed8c0f14ad8cbbb1c7bc12bf21725fa15c0e7ba326e433ec41ddfaf41d27aa18ce4381a61d187ecbdcc9740747d300b7f354bb68139f2306508a06a04fbe'

def alignment(tmp_ID, original_cipher_byte, plaintext_byte, round):
    return tmp_ID

plaintext = []
guess_plaintext = 0
i = 16
# for i in range(16, len(ID)/2):
original_byte = ID[-2*(i+1):len(ID)-2*i]

for j in range(256):
    '''Guess Unknown Bytes'''
    guess_byte = '{0:0>2x}'.format(j).encode()
    if guess_byte == original_byte:
        continue

    r.recvuntil(b'Your choice:')
    r.sendline(b'2')
    r.recvuntil(b'Your choice:')
    r.sendline(b'1')
    r.recvuntil(b'Please give me the ID (hex encoded): ')

    tmp_ID = ID[:-2*(i+1)] + guess_byte + ID[len(ID)-2*i:]
    print(tmp_ID)

    r.sendline(tmp_ID)
    padding_correct = True if 'Hint: It seems feasible...' in r.recvline().strip().decode() else False

    if padding_correct:
        log.info("The {} bytes is: {}".format(i, j))
        guess_plaintext = int(original_byte, 16)^j^(i%16+1)
        plaintext.append('{0:0>2x}'.format(guess_plaintext))
        break

nblock = len(ID) // 16
for block in range(1, nblock):
    block_pt = b""
    block_ct = ID[block * 16 : (block + 1) * 16]
    last_ct = ID[(block - 1) * 16 : block * 16]
    for idx in range(15, -1, -1):
        postfix = bytes([i ^ j for i, j in zip(block_pt, last_ct[idx + 1:])])
        prefix = last_ct[:idx]
        for i in range(256):
            now = prefix + bytes([i ^ last_ct[idx]]) + postfix + block_ct
            r.sendline(now)
            padding_correct = True if 'Hint: It seems feasible...' in r.recvline().strip().decode() else False
            if padding_correct:
                block_pt = bytes(i ^ 0x80) + block_pt
                break
        else:
            block_pt = bytes([0x80]) + block_pt


r.interactive()