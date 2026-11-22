//go:build unix

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func openAdminKeyOutput(path string) (*os.File, func(bool) error, error) {
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, nil, fmt.Errorf("open admin key output directory: %w", err)
	}
	name := filepath.Base(path)
	info, err := root.Stat(".")
	if err != nil {
		return nil, nil, errors.Join(err, root.Close())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 { // #nosec G115 -- effective Unix ID fits uid_t
		return nil, nil, errors.Join(fmt.Errorf("admin key output directory must be owned by this user and private (0700)"), root.Close())
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("create exclusive admin key output: %w", err), root.Close())
	}
	return f, func(commit bool) error {
		var syncErr error
		if commit {
			syncErr = f.Sync()
		}
		err := errors.Join(syncErr, f.Close())
		if !commit || err != nil {
			err = errors.Join(err, root.Remove(name))
		}
		return errors.Join(err, root.Close())
	}, nil
}
