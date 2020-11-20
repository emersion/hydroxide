// +build !windows

import (
	"errors"
	"os"
	"path/filepath"
)

func getConfigHome() (string, error) {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home := os.Getenv("HOME")
		if home == "" {
			return "", errors.New("HOME not set")
		}
		configHome = filepath.Join(home, ".config")
	}
	return configHome, nil
}