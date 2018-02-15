import sys
import cle
import angr
import claripy
import r2pipe

## extract inner code ##

p = r2pipe.open(sys.argv[1], flags=['-d'])
p.cmd('doo DUMMY_FLAG')
p.cmd('aaa')

for op in p.cmdj('pdfj @ main')['ops']:
    if op['opcode'] == 'call rdx':
        addr = op['offset']
        print 'decryption @', hex(addr)

p.cmd('db 0x%x' % addr)
p.cmd('dc')

rdx = p.cmdj('drj')['rdx']
print 'inner @', hex(rdx)

inner = ''
p.cmd('af @ 0x%x' % rdx)
for op in p.cmdj('pdfj @ 0x%x' % rdx)['ops']:
    inner += op['bytes'].decode('hex')

## angr ##

addr_flag  = 0x00008000
addr_stack = 0x007fffff
stack_size = 0x4000

temp = '/tmp/inner.junk'

with open(temp, 'w') as f:
    f.write(inner)

load = cle.loader.Loader(
    temp,
    main_opts = {
        'backend': 'blob',
        'custom_arch': cle.archinfo.ArchAMD64,
        'custom_entry_point': 0,
        'custom_base_addr': 0
    }
)

proj = angr.Project(load)

# store flag

size = 64 # some upper bound
flag = claripy.BVS('flag', (size + 1) * 8)
st   = proj.factory.call_state(0x0, flag, ret_addr=0xdeadbeef)

# needed to prevent the loop going into undefined memory
st.solver.add(flag.get_byte(size) == 0)

simgr = proj.factory.simgr(st)

while simgr.active:
    print simgr
    for s in simgr.active:
        if s.addr == 0xdeadbeef:
            s.solver.add(s.regs.eax == 0)
            try:
                print s.solver.eval(flag, cast_to=str)
                exit(0)
            except:
                pass
    simgr.step()
