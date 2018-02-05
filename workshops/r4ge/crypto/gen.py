s = 'flag{GoAheadDecrypt}'
s = map(ord, s)

import random

def line(ix, cx):

    v = 0
    for x in ix:
        v ^= s[x]
    for x in cx:
        v ^= x

    o = []
    o += map(lambda x: 's[%d]' % x, ix)
    o += map(lambda x: '%d' % x, cx)
    o += ['%d' % v]
    random.shuffle(o)
    return ' ^ '.join(o)

lines = []
lines.append('''
int check(char* s) {
    int l = 0;
    for (;s[l]; l++);
    if (l != 20)
        return 0;

    int v = 0;
''')


for i in range(40):
    idx = range(len(s))
    random.shuffle(idx)
    v = idx[:random.randrange(1, 6)]
    t = random.randrange(0, 256)
    lines.append('    v |= %s;' % line(v, [t]))

lines.append('    return !v;')
lines.append('}')
lines.append('''
int main(int argc, char** argv) {
    if (check(argv[1]))
        printf("ok\\n");
    return 0;
}
''')

for l in lines:
    print l
