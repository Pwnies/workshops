build:
	docker build -t binary_intro -f Dockerfile.build .
	docker run --rm -ti -v $(shell pwd):/build binary_intro

clean:
	rm example

.PHONY: clean
