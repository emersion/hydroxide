package config

import (
	"os"
	"path/filepath"
)

func Path(filename string) (string, error) {
	configHome, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	p := filepath.Join(configHome, "hydroxide", filename)

	dirname, _ := filepath.Split(p)
	if err := os.MkdirAll(dirname, 0700); err != nil {
		return "", err
	}

	return p, nil
}
