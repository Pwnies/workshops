import struct

F.<x> = GF(2^128, 'x', x^128 + x^7 + x^2 + x + 1)
G.<y> = PolynomialRing(F)

def bin(vs):
    '''
    Converts a list of bytes to a binary string
    '''

    o = ''
    for v in vs:
        o += '{:08b}'.format(ord(v))
    return o

def poly(bs):
    '''
    Constructs a polynomial in GF(2^128)[y]
    with the coefficients in bs
    '''

    p = 0
    for b in bs:
        p += b
        p *= y
    return p

def block_to_field(v):
    '''
    Converts an AES block (128-bits)
    to a field element in GF(2^128)
    '''

    assert len(v) == 16
    v = int(bin(v)[::-1], 2)
    return F.fetch_int(v)

def field_to_block(v):
    '''
    Converts an element from GF(2^128)
    to an AES block (128-bits)
    '''

    v = '{:0128b}'.format(v.integer_representation())
    v = int(v[::-1], 2)
    return ('%032x' % v).decode('hex')

def pad(ct):
    '''
    Splits and pads a ciphertext according to the standard
    and adds the length block
    '''

    size = len(ct) * 8

    if len(ct) % 16 != 0:
        ct += '\x00' * (16 - len(ct) % 16)

    last = struct.pack('<Q', 0) + struct.pack('<Q', size)
    tota = ct + last

    assert len(tota) % 16 == 0

    return [tota[i:i+16] for i in range(0, len(tota), 16)]
