import angr
import claripy
import time

proj = angr.Project('./angrmanagement')

FLAG_LEN = 0x20
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# Initial state:
st = proj.factory.full_init_state(
        args=['./angrmanagement'],
        auto_load_libs=False,
        add_options=angr.options.unicorn,
        stdin=flag,
)

# Constrain the first 28 bytes to be non-null and non-newline:
for k in flag_chars:
    #st.solver.add(k != 0)
    #st.solver.add(k != 10)
    st.solver.add(k >= b'\x20') # ' '
    st.solver.add(k <= b'\x7e') # '~'

print("SimulationManager: performing symbolic execution")
simgr = proj.factory.simulation_manager(st)

BASE = 0x400000
print("Base: " + str(BASE))
print("LOOK: " + str(BASE + 0x00102340))
simgr.explore(find=BASE + 0x00102340, avoid=BASE + 0x00102347)

for dead in simgr.deadended:
    print(bytes.fromhex(hex(dead.solver.eval(flag))[2:]))
    # One of them is: x#PAJGpmT[$D5^W[ph{A[70([.q?8A[j
"""
Enter the password:
x#PAJGpmT[$D5^W[ph{A[70([.q?8A[j
Correct!
gigem{4n63r_m4n463m3n7}
"""

