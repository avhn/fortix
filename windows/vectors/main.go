// Command vectors writes the Windows client interop vectors from the shared Go packages.
// With -check it compares the committed files byte for byte and exits 1 on any drift,
// so a protocol, profile, or share format change cannot silently diverge from the C# client.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// vectorFile pairs a file name under the interop directory with its deterministic generator.
type vectorFile struct {
	name     string
	generate func() (any, error)
}

// files lists every vector this module writes; credential-targets.json is only verified here.
var files = []vectorFile{
	{name: "protocol-frames.json", generate: protocolVectors},
	{name: "profile-validation.json", generate: profileVectors},
	{name: "share-format.json", generate: shareVectors},
}

// main parses flags, then writes or checks every vector file and reports drift by name.
func main() {
	dir := flag.String("dir", filepath.Join("..", "..", "testdata", "interop"), "interop vector directory")
	check := flag.Bool("check", false, "compare existing files instead of writing them")
	flag.Parse()
	drift := false
	if err := checkCredentials(*dir); err != nil {
		fmt.Fprintf(os.Stderr, "credential-targets.json: %v\n", err)
		drift = true
	}
	for _, file := range files {
		data, err := render(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", file.name, err)
			os.Exit(2)
		}
		path := filepath.Join(*dir, file.name)
		if *check {
			existing, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(existing, data) {
				fmt.Fprintf(os.Stderr, "%s: differs from generated vectors; run go run . in windows/vectors\n", file.name)
				drift = true
			}
			continue
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", file.name, err)
			os.Exit(2)
		}
	}
	if drift {
		os.Exit(1)
	}
}

// render generates one file as two-space indented JSON with a final newline.
// Go's default HTML escaping is kept so the files read the same as other repository fixtures.
func render(file vectorFile) ([]byte, error) {
	value, err := file.generate()
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
