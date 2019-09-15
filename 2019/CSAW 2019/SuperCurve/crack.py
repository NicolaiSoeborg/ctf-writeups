from supercurve import SuperCurve

curve = SuperCurve(
    field = 14753, order = 7919,
    a = 1, b = -1, g = (1, 1),
)
#curve = SuperCurve(
#    field = 14753, order = 14660,
#    a = 1, b = -1, g = (1, 1),
#)

lookup_table = {}
for secret_scalar in range(curve.order):
    pub = curve.mult(secret_scalar, curve.g)
    lookup_table[pub] = secret_scalar

"""
$ nc crypto.chal.csaw.io 1000
a = 1
b = -1
p = 14753
n = 7919
Public key: (1767, 6723)
What is the secret?
> 7762
flag{use_good_params}

$ python -i crack.py
>> lookup_table[(1767, 6723)]
7762

"""
