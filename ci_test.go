package dns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReflect(t *testing.T) {
	// don't let it linger if we do a top-level test, takes 16+s
	os.Remove("cmd/reflect/reflect")
	os.Remove("cmd/testserv/testserv")
}

func TestPrintln(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	subdirFiles, _ := filepath.Glob("*/*.go")
	files = append(files, subdirFiles...)

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			t.Errorf("failed to parse file %s: %v", file, err)
			continue
		}

		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// Check if it's an identifier (function call)
			if ident, ok := call.Fun.(*ast.Ident); ok {
				switch ident.Name {
				case "println":
					fallthrough
				case "print":
					pos := fset.Position(ident.Pos())
					t.Errorf("%s:%d:%d: use of %s()", file, pos.Line, pos.Column, ident.Name)

				default:
				}
			}
			return true
		})
	}
}
