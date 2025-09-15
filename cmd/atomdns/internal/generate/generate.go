package generate

import (
	"bytes"
	"go/format"
	"log"
	"os"
)

func Write(b *bytes.Buffer, out string) {
	formatted, err := format.Source(b.Bytes())
	if err != nil {
		b.WriteTo(os.Stderr)
		log.Fatalf("Failed to generate %s: %v", out, err)
	}

	if err := os.WriteFile(out, formatted, 0640); err != nil {
		log.Fatalf("Failed to generate %s: %v", out, err)
	}
}
