import r2pipe

from pwn import *

p = r2pipe.open('./inner.out')
p.cmd('aaaa')
p.cmd('s sym.check')
dis = p.cmdj('pdfj')
dis.keys()

bytes = ''
for d in dis['ops']:
    bytes += d['bytes']

c = bytes.decode('hex')

# print disasm(c)

c = map(ord, c)
c = ([0] * 8) + c
c += [0] * (8 - len(c) % 8)

import os
import xtea



pt  = ''.join(map(chr, c))

while 1:
    key = '\x00' * 12 + os.urandom(3) + '\x00'
    xt  = xtea.new(key, mode=xtea.MODE_ECB, endian='<')
    ct  = xt.encrypt(pt)

    if  ct.startswith('\x00'):
        break

print '// key : %s' % key.encode('hex')

xtT = xtea.new(key, mode=xtea.MODE_ECB, endian='<')
ptT = xt.decrypt(ct)

assert ptT == pt
assert ptT.startswith('\x00' * 8)
assert len(ct) == len(c)

ct  = map(ord, ct)
ct  = map(lambda x: '0x%02x' % x, ct)

print 'char code[] = {', ', '.join(ct), '};'
