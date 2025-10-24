reflect:
	go build

old.txt: reflect
	go test -v -count=1 | tee old.txt

new.txt: reflect
	go test -v -count=1 | tee new.txt

.PHONY:
stat: old.txt new.txt
	benchstat old.txt new.txt
