// Package icon generates and caches original ring glyphs for desktop trays.
package icon

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"

	"github.com/avhn/fortix/internal/tray/model"
)

// Frames is the number of evenly spaced arc positions in a connecting loop.
const Frames = 12

// key selects platform tint, pixel size, status, and connecting frame in the cache.
type key struct {
	platform string
	size     int
	status   model.Status
	frame    int
}

// cache holds immutable PNGs encoded once during package initialization.
var cache = generateCache()

// PNG returns a copy of a cached glyph for darwin or linux at 22 or 44 pixels.
// Connecting accepts frames 0 through 11; other statuses require frame zero.
// Unsupported inputs return an error rather than an ambiguous fallback glyph.
func PNG(platform string, size int, status model.Status, frame int) ([]byte, error) {
	data, ok := cache[key{platform, size, status, frame}]
	if !ok {
		return nil, errors.New("icon: unsupported platform, size, status, or frame")
	}
	return bytes.Clone(data), nil
}

// generateCache renders all supported glyphs, returning immutable encoded PNGs.
// Encoding into a bytes.Buffer cannot fail; an encoder failure is an invariant panic.
func generateCache() map[key][]byte {
	result := make(map[key][]byte, 64)
	for _, platform := range []string{"darwin", "linux"} {
		for _, size := range []int{22, 44} {
			for _, status := range []model.Status{model.NotConnected, model.Connecting, model.Connected, model.Partial, model.Attention} {
				count := 1
				if status == model.Connecting {
					count = Frames
				}
				for frame := range count {
					var buf bytes.Buffer
					if err := png.Encode(&buf, render(platform, size, status, frame)); err != nil {
						panic(err)
					}
					result[key{platform, size, status, frame}] = buf.Bytes()
				}
			}
		}
	}
	return result
}

// render returns a transparent ring glyph with four-by-four coverage sampling.
// Coordinates use a 22-pixel design grid so the 44-pixel retina shape is identical.
// Darwin pixels are strictly black with alpha for native menu bar template tinting.
func render(platform string, size int, status model.Status, frame int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	draw.Draw(img, img.Bounds(), image.Transparent, image.Point{}, draw.Src)
	tint := color.NRGBA{A: 255}
	if platform == "linux" {
		tint = color.NRGBA{R: 150, G: 158, B: 168, A: 255}
		switch status {
		case model.Connecting, model.Attention:
			tint = color.NRGBA{R: 204, G: 139, B: 20, A: 255}
		case model.Connected, model.Partial:
			tint = color.NRGBA{R: 38, G: 157, B: 91, A: 255}
		}
	}
	for y := range size {
		for x := range size {
			coverage := 0.0
			for sy := range 4 {
				for sx := range 4 {
					dx := (float64(x)+(float64(sx)+0.5)/4)*22/float64(size) - 11
					dy := (float64(y)+(float64(sy)+0.5)/4)*22/float64(size) - 11
					coverage += alphaAt(dx, dy, status, frame)
				}
			}
			pixel := tint
			pixel.A = uint8(math.Round(coverage * 255 / 16))
			img.SetNRGBA(x, y, pixel)
		}
	}
	return img
}

// alphaAt computes normalized coverage for one design-grid sample and frame.
// No I/O or errors occur; connecting advances clockwise from the top of the ring.
func alphaAt(x, y float64, status model.Status, frame int) float64 {
	radius := math.Hypot(x, y)
	ring := radius >= 7 && radius <= 9
	angle := math.Atan2(y, x) + math.Pi/2
	if angle < 0 {
		angle += 2 * math.Pi
	}
	switch status {
	case model.Connecting:
		if !ring {
			return 0
		}
		position := math.Mod(angle-float64(frame)*2*math.Pi/Frames+2*math.Pi, 2*math.Pi)
		if position < math.Pi/2 {
			return 1
		}
		return 0.35
	case model.Connected:
		if ring || radius <= 5 {
			return 1
		}
	case model.Partial:
		if ring || (radius <= 5 && x <= 0) {
			return 1
		}
	case model.Attention:
		// The right-hand gap leaves room for a separate attention dot.
		if math.Hypot(x-8, y) <= 1.6 || (ring && (x < 0 || math.Abs(y) > 3.5)) {
			return 1
		}
	default:
		if ring {
			return 1
		}
	}
	return 0
}
