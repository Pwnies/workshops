import angr
import struct
import claripy

value = claripy.BVS('value', 32)
proj  = angr.Project('./tree')
check = proj.loader.find_symbol('check')
st    = proj.factory.call_state(check.rebased_addr, value, ret_addr=0xdeadbeef)
simgr = proj.factory.simgr(st)

while simgr.active:
    print simgr
    for s in simgr.active:
        if s.addr == 0xdeadbeef:
            s.solver.add(s.regs.eax == 1)
            try:
                v = s.solver.eval(value, cast_to=str)
                print struct.unpack('i', v)[0]
            except:
                pass
    simgr.step()
