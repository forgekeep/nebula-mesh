package web

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// ErrQRTooLarge is returned when the input text exceeds the QR Level-L byte-mode
// capacity (2953 bytes).
var ErrQRTooLarge = errors.New("text exceeds QR Level-L byte-mode capacity (2953 bytes)")

// renderQRSVG encodes text as a QR code and renders it as an SVG string.
// Returns ErrQRTooLarge if text exceeds 2953 bytes.
func renderQRSVG(text string) (string, error) {
	if len(text) > 2953 {
		return "", ErrQRTooLarge
	}

	code, err := qr.Encode(text, qr.L, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("encode QR: %w", err)
	}

	// Scale to a reasonable size (each module becomes ~10px)
	code, err = barcode.Scale(code, 256, 256)
	if err != nil {
		return "", fmt.Errorf("scale QR: %w", err)
	}

	// Convert barcode.Barcode to SVG by inspecting the bitmap.
	// The barcode's Bounds() tells us the dimensions in modules.
	bounds := code.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Build SVG manually by examining each module.
	var buf bytes.Buffer
	moduleSize := 1 // in SVG units; total width = moduleSize * width

	fmt.Fprintf(&buf, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="256" height="256">`, width, height)

	// Iterate through each module and output black rectangles.
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// code.At(x, y) returns the color at that module.
			// Black modules return color.Black or similar (not color.White).
			r, g, b, a := code.At(x, y).RGBA()
			// If it's black (r=g=b=0, a=65535), output a rect.
			if r == 0 && g == 0 && b == 0 && a == 65535 {
				fmt.Fprintf(&buf, `<rect x="%d" y="%d" width="%d" height="%d" fill="#000"/>`,
					x*moduleSize, y*moduleSize, moduleSize, moduleSize)
			}
		}
	}
	fmt.Fprintf(&buf, `</svg>`)

	svg := buf.String()

	// Validate it's well-formed XML.
	if err := xml.Unmarshal([]byte(svg), &struct{}{}); err != nil {
		return "", fmt.Errorf("generated SVG is invalid XML: %w", err)
	}

	return svg, nil
}
