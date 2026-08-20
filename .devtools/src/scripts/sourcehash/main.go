package main

import (
	"fmt"
	"os"

	"github.com/acme/prompt-audit-template/internal/sourcehash"
)

func main() {
	digest, err := sourcehash.Compute(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(digest)
}
