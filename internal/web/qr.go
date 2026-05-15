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

	// Build SVG manually by examining each module. The QR spec recommends a
	// quiet zone (white border) of at least 4 modules — without it scanners
	// often refuse to lock on, especially when the surrounding page is dark.
	var buf bytes.Buffer
	moduleSize := 1 // SVG units per module
	quietZone := 16 // white border around the QR, in SVG units
	viewSize := width*moduleSize + 2*quietZone

	fmt.Fprintf(&buf, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="288" height="288" shape-rendering="crispEdges">`, viewSize, viewSize)
	// White background covering the full viewBox so the QR reads on any theme.
	fmt.Fprintf(&buf, `<rect width="%d" height="%d" fill="#fff"/>`, viewSize, viewSize)

	// Iterate through each module and output black rectangles, offset by quietZone.
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, b, a := code.At(x, y).RGBA()
			if r == 0 && g == 0 && b == 0 && a == 65535 {
				fmt.Fprintf(&buf, `<rect x="%d" y="%d" width="%d" height="%d" fill="#000"/>`,
					quietZone+x*moduleSize, quietZone+y*moduleSize, moduleSize, moduleSize)
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
