package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
)

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	return writeThrough(path, data, perm, os.Rename)
}

func atomicCreate(path string, data []byte, perm os.FileMode) error {
	return writeThrough(path, data, perm, os.Link)
}

func writeThrough(path string, data []byte, perm os.FileMode, place func(tmp, path string) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sshstate-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := place(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync directory %s: %w", dir, err)
	}
	return nil
}
