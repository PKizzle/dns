package dbhost

import (
	"os"
	"testing"
)

func TestSetup(t *testing.T) {
	f, err := os.Open("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dbhost := new(Dbhost)
	dbhost.Load(f)
}
