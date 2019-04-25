import angr, claripy

proj = angr.Project('high_quality_checks')

state = proj.factory.entry_state()

arg1 = claripy.BVS('arg1', 20*8)

initial_state = proj.factory.entry_state(args=["high_quality_checks", arg1])

simgr = proj.factory.simulation_manager(initial_state)

simgr.explore(find=0x400ad2, avoid=[])

print(simgr.found[0].posix.dumps(0))  # actf{fun_func710n5}
