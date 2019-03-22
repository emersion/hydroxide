package config

import (
	"errors"
	"os"
	"path/filepath"
)

func Path(filename string) (string, error) {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home := os.Getenv("HOME")
		if home == "" {
			return "", errors.New("HOME not set")
		}
		configHome = filepath.Join(home, ".config")
	}

	p := filepath.Join(configHome, "hydroxide", filename)

	dirname, _ := filepath.Split(p)
	if err := os.MkdirAll(dirname, 0700); err != nil {
		return "", err
	}

	return p, nil
}
