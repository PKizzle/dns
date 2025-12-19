package dnstest

import "testing"

func TestServer(t *testing.T) {
	// mostly to check if it will not hang
	cancel, listen, err := Server(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	t.Logf("%s", listen)
}

func TestServerHTTP(t *testing.T) {
	cancel, listen, err := HTTPServer(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	t.Logf("%s", listen)
}
