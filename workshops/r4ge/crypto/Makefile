inner.c: gen.py
	python gen.py > inner.c

inner.out: inner.c
	gcc -fPIE inner.c -o inner.out

code.c: build.py inner.c
	python build.py > code.c

obf: outer.c build.py code.c
	gcc -std=gnu99 outer.c -o obf
