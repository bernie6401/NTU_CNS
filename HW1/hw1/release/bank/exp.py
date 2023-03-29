from pwn import *

context.arch = 'amd64'

for i in range(2):
    # r = process('./server.py')
    r = remote('cns.csie.org', 44377)

    magic1 = open('shattered-1.pdf', 'rb').read() + b'I love CNS'
    magic2 = open('shattered-2.pdf', 'rb').read() + b'I love CNS'

    '''Register "I love CNS and get the passkey"'''
    r.recvuntil(b'Your choice: ')
    r.sendline(b'1')
    r.recvuntil(b'Username: ')
    r.sendline(magic1)
    passkey = r.recvline().decode('utf-8').split(': ')[1].replace('\n', '')
    log.info("Normal account passkey: {}".format(passkey))

    '''Register another account that has same sha1 value with previous one'''
    r.recvuntil(b'Your choice: ')
    r.sendline(b'1')
    r.recvuntil(b'Username: ')

    r.sendline(magic2)
    passkey_collision = r.recvline().decode('utf-8').split(': ')[1].replace('\n', '')
    log.info("Collision account passkey: {}".format(passkey_collision))

    '''Login Normal Account and Get money'''
    r.recvuntil(b'Your choice: ')
    r.sendline(b'2')
    r.recvuntil(b'Username: ')
    r.sendline(magic1)
    r.recvuntil(b'Passkey in Base64: ')
    r.sendline(passkey.encode())

    '''Logout'''
    r.recvuntil(b'Your choice: ')
    r.sendline(b'1')

    '''Login Collision Account'''
    r.recvuntil(b'Your choice: ')
    r.sendline(b'2')
    r.recvuntil(b'Username: ')
    r.sendline(magic2)
    r.recvuntil(b'Passkey in Base64: ')
    r.sendline(passkey_collision.encode())

    '''Logout'''
    r.recvuntil(b'Your choice: ')
    r.sendline(b'1')

    '''Login Normal Account and Get money'''
    r.recvuntil(b'Your choice: ')
    r.sendline(b'2')
    r.recvuntil(b'Username: ')
    r.sendline(magic1)
    r.recvuntil(b'Passkey in Base64: ')
    r.sendline(passkey.encode())

    r.recvuntil(b'You have $')
    money = r.recvline().decode().split(" ")[0]
    log.info("Your money is: {}".format(money))

    r.recvuntil(b'Your choice: ')
    if i == 0:
        r.sendline(b'2')
        r.recvuntil(b'Here is your flag 1:')
        flag1 = r.recvline().strip().decode()
        log.info("Flag1: {}".format(flag1))
    elif i == 1:
        r.sendline(b'3')
        r.recvuntil(b'Here is your flag 2:')
        flag2 = r.recvline().strip().decode()
        log.info("Flag2: {}".format(flag2))

    r.close()

r.interactive()