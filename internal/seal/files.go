package seal

import (
	"os"
	"path/filepath"
)

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".sealcheck-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
