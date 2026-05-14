package pki

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultAgentCertDuration_Value(t *testing.T) {
	expected := 30 * 24 * time.Hour
	assert.Equal(t, expected, DefaultAgentCertDuration)
}

func TestDefaultMobileCertDuration_Value(t *testing.T) {
	expected := 365 * 24 * time.Hour
	assert.Equal(t, expected, DefaultMobileCertDuration)
}
