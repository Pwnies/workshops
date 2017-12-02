import struct

F.<x> = GF(2^128, 'x', x^128 + x^7 + x^2 + x + 1)
G.<y> = PolynomialRing(F)

def bin(vs):
    o = ''
    for v in vs:
        o += '{:08b}'.format(ord(v))
    return o

def poly(bs):
    p = 0
    for b in bs:
        p += b
        p *= y
    return p

def block_to_field(v):
    assert len(v) == 16 # AES blocksize
    v = int(bin(v)[::-1], 2)
    return F.fetch_int(v)

def field_to_block(v):
    v = '{:0128b}'.format(v.integer_representation())
    v = int(v[::-1], 2)
    return ('%032x' % v).decode('hex')

b = '\xde\xad\xbe\xef' * 4
assert field_to_block(block_to_field(b)) == b

def mac(h, bs):
    # h : authentication key (input to poly)
    g = 0
    for b in bs:
        g += b
        g *= h

def split(ct):
    return (ct[:8], ct[8:-16], ct[-16:])

def pad(ct):


    size = len(ct) * 8

    if len(ct) % 16 != 0:
        ct += '\x00' * (16 - len(ct) % 16)

    last = struct.pack('<Q', 0) + struct.pack('<Q', size)
    tota = ct + last

    print tota.encode('hex')

    assert len(tota) % 16 == 0

    return [tota[i:i+16] for i in range(0, len(tota), 16)]

def attack(pay1, pay2):

    iv1, ct1, tag1 = split(pay1)
    iv2, ct2, tag2 = split(pay2)

    blk1 = pad(ct1)
    blk2 = pad(ct2)

    assert iv1 == iv2

    # construct poly evaluated

    poly1 = poly(map(block_to_field, blk1))
    poly2 = poly(map(block_to_field, blk2))

    # move all terms to one side

    poly1 -= block_to_field(tag1)
    poly2 -= block_to_field(tag2)

    base = poly1 - poly2

    return base.roots()

def load(path):
    with open(path, 'r') as f:
        return bytes(f.read().decode('hex'))

ct1 = load('sample1.tmp')
ct2 = load('sample2.tmp')

for (h, _) in attack(ct1, ct2):

    # recover pad

    iv, ct, tag = split(ct1)

    print iv.encode('hex'), ct.encode('hex'), tag.encode('hex')

    chk = pad(ct)
    p   = poly(map(block_to_field, chk))
    s   = block_to_field(tag) - p(h)

    print 'h:', h
    print 's:', s

    # double check against known ct

    _, ctT, tagT = split(ct2)
    chkT         = pad(ctT)
    pT           = poly(map(block_to_field, chkT)) + s
    tagTP        = pT(h)

    assert field_to_block(tagTP) == tagT

    # flip bits in ct

    ctP = map(ord, ct)
    ctP[10] ^^= ord('0')
    ctP[10] ^^= ord('1')
    ctP = ''.join(map(chr, ctP))

    # recompute mac

    chkP = pad(ctP)
    pP   = poly(map(block_to_field, chkP)) + s
    tP   = pP(h)

    print 'new tag:', tP

    tagP = field_to_block(tP)

    assert tagP != tag

    ctF  = iv + ctP + tagP

    print ctF.encode('hex')

    raw_input('')
