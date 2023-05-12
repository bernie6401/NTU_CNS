tmp = input().replace(" ", "").split("×")
p, q = int(tmp[0]), int(tmp[1])

from Crypto.Util.number import inverse
phi_n = (p - 1) * (q - 1)
e = 65537
print(inverse(e, phi_n))