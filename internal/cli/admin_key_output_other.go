//go:build !unix

package cli

import (
	"errors"
	"os"
)

func openAdminKeyOutput(_ string) (*os.File, func(bool) error, error) {
	return nil, nil, errors.New("protected --output is supported on Unix; use an interactive terminal")
}
