reflect:
	go build

old.txt: reflect
	go test -v -count=1 | tee old.txt
