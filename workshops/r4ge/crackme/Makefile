obf: outer.c build.py code.c
	gcc -std=gnu99 outer.c -o obf

inner.c: gen.py
	python gen.py > inner.c

inner.out: inner.c
	gcc -fPIE inner.c -o inner.out

code.c: build.py inner.out
	python build.py > code.c

obf-hard: obf
	strip obf -o obf-hard

clean:
	rm -f obf
	rm -f obf-hard
	rm -f inner.c
	rm -f inner.out
	rm -f code.c

upload: obf obf-hard inner.c outer.c
	scp inner.c outer.c obf obf-hard hugo@rot256.io:~/public

.PHONY: clean upload
