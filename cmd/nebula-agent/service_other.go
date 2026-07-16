//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
)

func runService(context.Context, []string, io.Writer, io.Writer) error {
	return fmt.Errorf("service management is only supported on Windows")
}
