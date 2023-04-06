from pwn import *
from tqdm import trange
from itertools import cycle
from tqdm import trange

r = remote('cns.csie.org', 44399)
context.arch = 'amd64'


r.recvuntil(b'Your choice:')
r.sendline(b'1')
r.recvuntil(b'Please speak out the secret word: ')
r.sendline(b'CNS{Aka_BIT_f1ipp1N9_atTaCk!}')


for i in trange(2**16):
    r.recvuntil(b'Your choice:')
    r.sendline(b'1')
    r.recvuntil(b'Please enter your ID (hex encoded): ')


    ID_prefix = '{0:0>4x}'.format(i)
    ID_fake_1 = '9f98653e87df804263d5a0348f11'# 7030
    ID_fake_2 = ''
    # print(ID_fake_2)
    ID_fake_3 = '5C36bc7c2cddfe02ffd4452808363540'  # XOR_Patch
    ID_postfix = '4815ed8c0f14ad8cbbb1c7bc12bf21725fa15c0e7ba326e433ec41ddfaf41d27aa18ce4381a61d187ecbdcc9740747d300b7f354bb68139f2306508a06a04fbe'

    r.sendline((ID_prefix + ID_fake_1 + ID_fake_2 + ID_fake_2 + ID_postfix).encode())

    response = r.recvline().strip().decode()
    # print(response)
    
    if 'Authentication failed' not in response:
        log.info("The magic number is: {}".format(i))
        print(ID_prefix + ID_fake_1 + ID_fake_2 + ID_fake_2 + ID_postfix)
        print(response)
        break
log.info("QAQ~~")