# Params:
exec(open("krypteret.txt", "rt").read()) ; e = 0x10001

# Calc p, q:
from math import isqrt
p = q = isqrt(n)
assert p * q == n

# Note p != q in RSA, so we have to calc phi(n) like this:
phi = p * (p - 1)
# normally: phi = (p-1)*(q-1)

d = pow(e, -1, phi)

print(bytes.fromhex(hex(pow(ct, d, n))[2:]).decode())
# NC3{3t_pr1mt4l_1_hånd3n_3r_b3dr3_3nd_t0_på...3ll3r_v3nt}
