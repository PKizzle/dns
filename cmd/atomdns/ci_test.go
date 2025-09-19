package main

import (
	"os"
)

func init() {
	os.Remove("atomdns")
}
