import angr
import claripy

arg1 = claripy.BVS('arg1', 8 * 10)
proj = angr.Project('./fib')

st = proj.factory.entry_state(args=['./fib', arg1])
sm = proj.factory.simulation_manager(st)
sm.explore()

print sm.deadended

for state in sm.deadended:
    a = state.solver.eval(arg1, cast_to=str)
    print a.encode('hex'), map(ord, a)
