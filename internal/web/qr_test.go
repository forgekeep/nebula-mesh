package web

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderQRSVG_KnownInput(t *testing.T) {
	svg, err := renderQRSVG("hello world")
	require.NoError(t, err)
	require.NotEmpty(t, svg)
	require.Contains(t, svg, "<svg")
	require.Contains(t, svg, "<rect")
	require.Contains(t, svg, "</svg>")

	// Verify it's valid XML
	var root interface{}
	err = xml.Unmarshal([]byte(svg), &root)
	require.NoError(t, err, "SVG should be valid XML")
}

func TestRenderQRSVG_LargeInput(t *testing.T) {
	// Input exceeding Level-L byte-mode capacity (2953 bytes)
	largeInput := strings.Repeat("a", 3000)
	svg, err := renderQRSVG(largeInput)
	require.Equal(t, ErrQRTooLarge, err)
	require.Empty(t, svg)
}

func TestRenderQRSVG_RoundTripSmoke(t *testing.T) {
	// Simulate a ~2KB YAML payload (typical mobile bundle size)
	yaml := strings.Repeat("nebula yaml: blah\n", 100) // ~1700 bytes
	svg, err := renderQRSVG(yaml)
	require.NoError(t, err)
	require.NotEmpty(t, svg)
	require.Contains(t, svg, "<svg")
	require.Contains(t, svg, "<rect")
}

func TestRenderQRSVG_EdgeCase_Exactly2953(t *testing.T) {
	// Exactly at the limit
	input := strings.Repeat("x", 2953)
	svg, err := renderQRSVG(input)
	require.NoError(t, err)
	require.NotEmpty(t, svg)
}

func TestRenderQRSVG_EdgeCase_Just2954(t *testing.T) {
	// Just over the limit
	input := strings.Repeat("x", 2954)
	svg, err := renderQRSVG(input)
	require.Equal(t, ErrQRTooLarge, err)
	require.Empty(t, svg)
}
