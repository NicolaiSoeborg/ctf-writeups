#from z3 import *
#
#s = Solver()
#k = BitVec('k', 128)
#
#pairs = [
#    (0x029abc13947b5373b86a1dc1d423807a, 0xb36b6b62a7e685bd1158744662c5d04a),
#    (0xeeb83b72d3336a80a853bf9c61d6f254, 0x614d86b5b6653cdc8f33368c41e99254),
#    (0x7a0e5ffc7208f978b81475201fbeb3a0, 0x292a7ff7f12b4e21db00e593246be5a0),
#    (0xc464714f5cdce458f32608f8b5e2002e, 0x64f930da37d494c634fa22a609342ffe),
#    (0xf944aaccf6779a65e8ba74795da3c41d, 0xaa3825e62d053fb0eb8e7e2621dabfe7),
#    (0x552682756304d662fa18e624b09b2ac5, 0xf2ffdf4beb933681844c70190ecf60bf)
#]
#
N = 2**128
#for (pt, ct) in pairs:
#    assert pt < N
#    tmp = BitVecVal(pt, 128)
#    for _ in range(765):
#        #tmp = (tmp + k) % N
#        tmp = tmp + k
#        tmp = tmp ^ k
#    s.add( tmp == ct )

# >>> s.check()
# sat
# >>> mod = s.model()
# >>> mod
# [k = 62900030173734087782946667685685220617]
k = 62900030173734087782946667685685220617
ct = 0x43713622de24d04b9c05395bb753d437

def decrypt(msg, key):
    tmp = msg
    for _ in range(765):
        tmp ^= key
        tmp = (tmp - key) % N
    return tmp

print("TWCTF{" + hex(decrypt(ct, k))[2:] + "}")
