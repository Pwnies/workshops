import r2pipe

p = r2pipe.open('./inner.out')
p.cmd('aaaa')
p.cmd('s sym.check')
dis = p.cmdj('pdfj')

dis.keys()

bytes = ''
for d in dis['ops']:
    bytes += d['bytes']

c = bytes.decode('hex')
c = map(ord, c)

c += [0] * (8 - len(c) % 8)

c = ([0] * 8) + c

import os
import xtea

key = '\x00' * 13 + os.urandom(3)
xt  = xtea.new(key, mode=xtea.MODE_ECB)
ct  = xt.encrypt(''.join(map(chr, c)))

ct  = map(ord, ct)
ct  = map(lambda x: '0x%02x' % x, ct)

print 'char code[] = {', ', '.join(ct), '}'

