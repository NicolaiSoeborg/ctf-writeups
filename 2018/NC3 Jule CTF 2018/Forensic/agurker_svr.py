import pickle

with open('agurker_svr', 'rb') as f:
    data = pickle.load(f)

flag = ''.join(v for (k, v) in sorted(data.items(), key=lambda kv: kv[0]))
print(bytes.fromhex(flag))
