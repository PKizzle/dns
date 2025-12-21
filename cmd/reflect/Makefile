MACHINE := $(shell uname -m)

ARCH := $(patsubst aarch64,arm64,$(MACHINE))
ARCH := $(patsubst x86_64,amd64,$(ARCH))

reflect:
	go build

old.txt: | reflect
	mkdir -p $(ARCH)
	go test -v -count=1 | tee $(ARCH)/old.txt

new.txt: | reflect
	mkdir -p $(ARCH)
	go test -v -count=1 | tee $(ARCH)/new.txt

.PHONY: stat
stat: $(ARCH)/old.txt $(ARCH)/new.txt
	benchstat $(ARCH)/old.txt $(ARCH)/new.txt

.PHONY: clean
clean:
	rm $(ARCH)/new.txt
