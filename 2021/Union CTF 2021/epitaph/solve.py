"""
Reversing the flash code using "jpexs-decompiler"
Then reimplementing and bruteforcing a single byte at a time:
"""

VM_SBOX = []
i = 0
while i < 256:
   VM_SBOX.append(127 - i & 255 ^ 55)
   i += 1

# Enum stuff:
def O(param1: str, param2: int, param3: list): return {'tag': param1, 'index': param2, 'params': param3}
def O1(param1: int, param2: int):              return O("O1", 0, [param1, param2])
def O2(param1: int, param2: int):              return O("O2", 1, [param1, param2])
def O3(param1: int, param2: int, param3: int): return O("O3", 2, [param1, param2, param3])
def O4(param1: int, param2: int, param3: int): return O("O4", 3, [param1, param2, param3])
def O5(param1: int, param2: int, param3: int): return O("O5", 4, [param1, param2, param3])
def O6(param1: int):                           return O("O6", 5, [param1])
def O7(param1: int, param2: int, param3: int): return O("O7", 6, [param1, param2, param3])
def O8(param1: int, param2: int):              return O("O8", 7, [param1, param2])
def O9(param1: int):                           return O("O9", 8, [param1])
def OA(param1: int, param2: int, param3: int): return O("OA", 9, [param1, param2, param3])
def OB(param1: int, param2: int):              return O("OB", 10, [param1, param2])

VM_code = [
    O1(285,0),
    O2(272,264),
    O2(273,265),
    O2(274,266),
    O2(275,267),
    O2(276,268),
    O2(277,269),
    O2(278,270),
    O2(279,271),
    O2(280,272),
    O1(281,0),
    O1(282,0),
    O5(280,256,282),
    O3(283,0,280),
    O6(282),
    O2(284,282),
    O8(284,3),
    O5(283,272,284),
    O2(280,283),
    O9(280),
    O4(272,284,280),
    OA(282,8,12),
    O6(281),
    OA(281,32,11),
    O2(264,272),
    O7(286,285,264),
    O6(285),
    O2(265,273),
    O7(286,285,265),
    O6(285),
    O2(266,274),
    O7(286,285,266),
    O6(285),
    O2(267,275),
    O7(286,285,267),
    O6(285),
    O2(268,276),
    O7(286,285,268),
    O6(285),
    O2(269,277),
    O7(286,285,269),
    O6(285),
    O2(270,278),
    O7(286,285,270),
    O6(285),
    O2(271,279),
    O7(286,285,271),
    O6(285),
    OB(286,285),
    OA(284,9,1)
]

FLAG = [255, 238, 46, 22, 7, 209, 30, 68, 133, 2, 125, 35, 7, 245, 28, 18, 131, 77, 172, 159, 26, 194, 92, 66, 70, 117, 36, 59, 31, 153, 51, 27, 215, 215, 70, 178, 111, 172, 106, 39]
NUMROUNDS = 32

def VM_P(param1: list):
    """ PKCS#5 padding """
    _loc2_ = param1.copy()
    i = 1
    while (len(param1) + i) % 8 != 0:
        i += 1

    j = 0
    while j < i:
        _loc2_.append(i)
        j += 1

    return _loc2_

def VM_E(param1: list):
    idx = 0
    # loop0:
    while idx < len(VM_code):
        _loc3_ = VM_code[idx]
        idx += 1
        if _loc3_["index"] == 0:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            param1[arg0] = arg1
            continue
        if _loc3_["index"] == 1:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            param1[arg0] = param1[arg1]
            continue
        if _loc3_["index"] == 2:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            arg2 = _loc3_["params"][2]
            param1[arg0] = param1[arg1 + (param1[arg2])]
            continue
        if _loc3_["index"] == 3:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            arg2 = _loc3_["params"][2]
            param1[arg0 + param1[arg1]] = param1[arg2]
            continue
        if _loc3_["index"] == 4:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            arg2 = _loc3_["params"][2]
            param1[arg0] = param1[arg0] + (param1[arg1 + (param1[arg2])]) & 255
            continue
        if _loc3_["index"] == 5:
            arg0 = _loc3_["params"][0]
            param1[arg0] = (param1[arg0]) + 1 & 255
            continue
        if _loc3_["index"] == 6:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            arg2 = _loc3_["params"][2]
            param1[arg0 + param1[arg1]] = param1[arg0 + param1[arg1]] ^ param1[arg2]
            continue
        if _loc3_["index"] == 7:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            param1[arg0] = param1[arg0] & arg1
            continue
        if _loc3_["index"] == 8:
            arg0 = _loc3_["params"][0]
            param1[arg0] = (((param1[arg0]) << 1) | ((param1[arg0]) >> 7)) & 255
            continue
        if _loc3_["index"] == 9:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            arg2 = _loc3_["params"][2]
            if param1[arg0] < arg1:
                idx = arg2
            continue
        if _loc3_["index"] ==  10:
            arg0 = _loc3_["params"][0]
            arg1 = _loc3_["params"][1]
            if arg0 + param1[arg1] >= len(param1):
                break  # loop0;
            continue
        else:
            continue
    return param1

def VM_X(param1: list):
    _loc2_ = []
    i = 0
    _loc4_ = "initiªl!"
    while i < len(_loc4_):
        _loc5_ = ord(_loc4_[i])  # .charCodeAt(i)
        i += 1
        _loc2_.append(_loc5_)

    _loc7_ = []
    i = 0
    _loc4_ = "S3CRET__"
    while i < len(_loc4_):
        _loc5_ = ord(_loc4_[i])  # .charCodeAt(i)
        i += 1
        _loc7_.append(_loc5_)

    _loc3_ = 286
    state = []
    i = 0
    while i < _loc3_ + len(param1):
        i += 1
        state.append(0)

    i = 0
    while i < 256:
        state[i] = VM_SBOX[i]
        i += 1

    state[256] = _loc7_[0]
    state[257] = _loc7_[1]
    state[258] = _loc7_[2]
    state[259] = _loc7_[3]
    state[260] = _loc7_[4]
    state[261] = _loc7_[5]
    state[262] = _loc7_[6]
    state[263] = _loc7_[7]
    state[264] = _loc2_[0]
    state[265] = _loc2_[1]
    state[266] = _loc2_[2]
    state[267] = _loc2_[3]
    state[268] = _loc2_[4]
    state[269] = _loc2_[5]
    state[270] = _loc2_[6]
    state[271] = _loc2_[7]

    i = 0
    while i < len(param1):
        state[_loc3_ + i] = param1[i]
        i += 1
    
    state = VM_E(state)
    return  state[_loc3_:] # state.slice(_loc3_)

def main(guess: bytes):
    # input.maxChars = 48;
    # input.text = "union{...}" => guess
    _loc2_ = [c for c in guess]

    state = VM_X(VM_P(_loc2_))
    foundFlag = True
    
    if len(state) != len(FLAG):
        print(f"Bad guess length: {len(state)} should be {len(FLAG)}")
        foundFlag = False

    i = 0
    while i < len(FLAG):
        if state[i] != FLAG[i]:
            foundFlag = False
            return i  #return f'Bad char at {i}: {state[i]} != {FLAG[i]}'
        i += 1

    if foundFlag:
        input(f"FOUND FLAG: {guess}")
    return foundFlag


if __name__ == '__main__':
    known_prefix = b""
    while True:
        mypad = b'?' * (35 - len(known_prefix))
        for c in range(256):
            num_good = main(known_prefix + bytes([c]) + mypad + b"}")
            if num_good == len(known_prefix) + 1:
                print(f"Guess: {known_prefix} + {chr(c)}")
                known_prefix += bytes([c])
                break

# Flag: union{rest_in_p3ac3_sh0ckw44v3_:(}
