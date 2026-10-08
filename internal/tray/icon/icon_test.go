// Package icon tests cached glyph geometry, PNG validity, and reproducibility.
package icon

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/tray/model"
)

// updateGolden permits explicit regeneration of the per-frame SHA-256 fixture.
var updateGolden = flag.Bool("update-golden", false, "regenerate icon frame hashes")

// TestGolden compares decoded NRGBA pixel hashes for each platform, size, status, and frame.
// It also generates each frame again independently, detecting mutable cache corruption.
func TestGolden(t *testing.T) {
	var hashes strings.Builder
	for _, platform := range []string{"darwin", "linux"} {
		for _, size := range []int{22, 44} {
			for _, status := range []model.Status{model.NotConnected, model.Connecting, model.Connected, model.Partial, model.Attention} {
				count := 1
				if status == model.Connecting {
					count = Frames
				}
				for frame := range count {
					data, err := PNG(platform, size, status, frame)
					if err != nil {
						t.Fatal(err)
					}
					img, err := png.Decode(bytes.NewReader(data))
					if err != nil || img.Bounds().Dx() != size || img.Bounds().Dy() != size {
						t.Fatalf("invalid PNG: %v", err)
					}
					pixels := image.NewNRGBA(img.Bounds())
					draw.Draw(pixels, pixels.Bounds(), img, img.Bounds().Min, draw.Src)
					again := render(platform, size, status, frame)
					if !bytes.Equal(pixels.Pix, again.Pix) {
						t.Fatal("nondeterministic rendering")
					}
					fmt.Fprintf(&hashes, "%s %d %s %d %x\n", platform, size, status, frame, sha256.Sum256(pixels.Pix))
					if platform == "darwin" {
						for y := range size {
							for x := range size {
								r, g, b, _ := img.At(x, y).RGBA()
								if r != 0 || g != 0 || b != 0 {
									t.Fatal("template has color")
								}
							}
						}
					}
					data[0] = 0
					pristine, err := PNG(platform, size, status, frame)
					if err != nil || pristine[0] == 0 {
						t.Fatal("cache escaped")
					}
				}
			}
		}
	}
	path := filepath.Join("testdata", "frames.sha256")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(hashes.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(expected) != hashes.String() {
		t.Fatalf("frame hashes changed\n%s", hashes.String())
	}
}

// TestContactSheet writes a labeled-by-order sheet for optional manual inspection.
// Rows pair darwin and linux at 22 and 44 pixels on light and dark backgrounds.
// Columns are idle, 12 connecting frames, up, partial, attention.
func TestContactSheet(t *testing.T) {
	sheet := image.NewNRGBA(image.Rect(0, 0, 16*48, 8*48))
	draw.Draw(sheet, sheet.Bounds(), image.White, image.Point{}, draw.Src)
	for row := range 8 {
		platform := []string{"darwin", "linux"}[row%2]
		size := []int{22, 44}[(row/2)%2]
		if row >= 4 {
			draw.Draw(sheet, image.Rect(0, row*48, 16*48, (row+1)*48), image.Black, image.Point{}, draw.Src)
		}
		column := 0
		for _, status := range []model.Status{model.NotConnected, model.Connecting, model.Connected, model.Partial, model.Attention} {
			count := 1
			if status == model.Connecting {
				count = Frames
			}
			for frame := range count {
				data, err := PNG(platform, size, status, frame)
				if err != nil {
					t.Fatal(err)
				}
				img, err := png.Decode(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				// Tint template pixels white to model native dark menu bar rendering.
				if platform == "darwin" && row >= 4 {
					tinted := image.NewNRGBA(img.Bounds())
					draw.DrawMask(tinted, tinted.Bounds(), image.White, image.Point{}, img, image.Point{}, draw.Src)
					img = tinted
				}
				offset := (48 - size) / 2
				draw.Draw(sheet, image.Rect(column*48+offset, row*48+offset, column*48+offset+size, row*48+offset+size), img, image.Point{}, draw.Over)
				column++
			}
		}
	}
	var data bytes.Buffer
	if err := png.Encode(&data, sheet); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "contact-sheet.png")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("contact sheet: %s", path)
}

// TestInvalidInputs rejects unsupported glyph requests instead of returning a wrong icon.
func TestInvalidInputs(t *testing.T) {
	for _, tc := range []key{{"windows", 22, model.Connected, 0}, {"darwin", 23, model.Connected, 0}, {"linux", 22, "invalid", 0}, {"linux", 22, model.Connecting, -1}, {"darwin", 44, model.Connecting, 12}, {"darwin", 22, model.Connected, 1}} {
		if _, err := PNG(tc.platform, tc.size, tc.status, tc.frame); err == nil {
			t.Fatal(tc)
		}
	}
}
