from pwn import *
from tqdm import trange
from itertools import cycle

r = remote('cns.csie.org', 44399)
context.arch = 'amd64'


r.recvuntil(b'Your choice:')
r.sendline(b'2')


def test_validity(response, error):
    padding_correct = True if error != response else False
    return padding_correct

def split_len(seq, length):
    return [seq[i : i + length] for i in range(0, len(seq), length)]

def block_search_byte(size_block, i, pos, l):
    
    # If ct_pos = 10 and
    # i = 0 return: 0000000000000000000000000000000a
    # i = 1 return: 00000000000000000000000000000a
    # i = 2 return: 000000000000000000000000000a
    # ...
    # i = 15 return: 0a
    
    hex_char = hex(pos).split("0x")[1]
    return ("00" * (size_block - (i + 1)) + ("0" if len(hex_char) % 2 != 0 else "") + hex_char + "".join(l))

def block_padding(size_block, i):
    
    # It'll return 
    # '00000000000000000000000000000001'
    # '00000000000000000000000000000202'
    # '00000000000000000000000000030303'
    # ...
    # '10101010101010101010101010101010'
    
    l = []
    for t in range(0, i + 1):
        l.append(("0" if len(hex(i + 1).split("0x")[1]) % 2 != 0 else "") + (hex(i + 1).split("0x")[1]))
    return "00" * (size_block - (i + 1)) + "".join(l)

def hex_xor(s1, s2):
    b = bytearray()
    for c1, c2 in zip(bytes.fromhex(s1), cycle(bytes.fromhex(s2))):
        b.append(c1 ^ c2)
    return b.hex()

def call_oracle(tmp_ID):
    r.recvuntil(b'Your choice:')
    r.sendline(b'1')
    r.recvuntil(b'Please give me the ID (hex encoded): ')
    # print(tmp_ID)

    r.sendline(tmp_ID.encode())
    

    return r.recvline().strip().decode()



cipher = '70309f98653e87df804263d5a0348f115c36bc7c2cddfe02ffd44528083635404815ed8c0f14ad8cbbb1c7bc12bf21725fa15c0e7ba326e433ec41ddfaf41d27aa18ce4381a61d187ecbdcc9740747d300b7f354bb68139f2306508a06a04fbe'
found = False
valide_value = []
result = []
size_block = 16
len_block = size_block * 2
cipher_block = split_len(cipher, len_block)
error = 'Hint: PADDING ERROR : incorrect padding'

if len(cipher_block) == 1:
    print("[-] Abort there is only one block")
    sys.exit()

# for each cipher_block
for block in reversed(range(1, len(cipher_block))):
    if len(cipher_block[block]) != len_block:
        print("[-] Abort length block doesn't match the size_block")
        break
    print("[+] Search value block : ", block, "\n")
    # for each byte of the block
    for i in range(0, size_block):
        # test each byte max 255
        for ct_pos in range(0, 256):
            # 1 xor 1 = 0 or valide padding need to be checked
            if ct_pos != i + 1 or ( len(valide_value) > 0 and int(valide_value[-1], 16) == ct_pos ):

                bk = block_search_byte(size_block, i, ct_pos, valide_value)
                bp = cipher_block[block - 1]
                bc = block_padding(size_block, i)

                tmp = hex_xor(bk, bp)
                # print(bk)
                cb = hex_xor(tmp, bc)

                if block == 5:
                    up_cipher = cipher_block[0] + cipher_block[1] + cipher_block[2] + cipher_block[3] + cb + cipher_block[5]
                elif block == 4:
                    up_cipher = cipher_block[0] + cipher_block[1] + cipher_block[2] + cb + cipher_block[4]
                elif block == 3:
                    up_cipher = cipher_block[0] + cipher_block[1] + cb + cipher_block[3]
                elif block == 2:
                    up_cipher = cipher_block[0] + cb + cipher_block[2]
                else:
                    up_cipher = cb + cipher_block[1]

                # we call the oracle, our god
                response = call_oracle( up_cipher )

                if test_validity(response, error):
                    found = True
                    print(up_cipher)

                    # data analyse and insert in right order
                    value = re.findall("..", bk)
                    valide_value.insert(0, value[size_block - (i + 1)])

                    bytes_found = "".join(valide_value)
                    if ( i == 0 and int(bytes_found, 16) > size_block and block == len(cipher_block) - 1 ):
                        print( "[-] Error decryption failed the padding is > " + str(size_block) )
                        sys.exit()

                    print( "\033[36m" + "\033[1m" + "[+]" + "\033[0m" + " Found", i + 1, "bytes :", bytes_found, )
                    print("")

                    break
        if found == False:
            # lets say padding is 01 for the last byte of the last block (the padding block)
            if len(cipher_block) - 1 == block and i == 0:
                value = re.findall("..", bk)
                valide_value.insert(0, "01")
            else:
                print("\n[-] Error decryption failed")
                result.insert(0, "".join(valide_value))
                hex_r = "".join(result)
                print("[+] Partial Decrypted value (HEX):", hex_r.upper())
                padding = int(hex_r[len(hex_r) - 2 : len(hex_r)], 16)
                print( "[+] Partial Decrypted value (ASCII):", bytes.fromhex(hex_r[0 : -(padding * 2)]).decode(), )
                sys.exit()
        found = False

    result.insert(0, "".join(valide_value))
    valide_value = []

print("")
hex_r = "".join(result)
print("[+] Decrypted value (HEX):", hex_r.upper())
padding = int(hex_r[len(hex_r) - 2 : len(hex_r)], 16)
print("[+] Decrypted value (ASCII):", bytes.fromhex(hex_r[0 : -(padding * 2)]).decode(),)


r.interactive()