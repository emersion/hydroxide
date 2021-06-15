package config

import (
	"errors"
	"os"
)

func getConfigHome() (string, error) {
	configHome := os.Getenv("APPDATA")
	if configHome == "" {
		return "", errors.New("APPDATA not set")
	}
	return configHome, nil
}