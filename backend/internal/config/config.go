package config

import (
	"os"
)

type Config struct {
	Port            string
	JWTSecret       string
	DataDir         string
	ServerPublicURL string
}

func Load() *Config {
	return LoadConfig()
}

func LoadConfig() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "siem-dev-secret-super-secure-key-32-chars-long"
	}

	dataDir := os.Getenv("DATABASE_DIR")
	if dataDir == "" {
		dataDir = "siem_data"
	}

	return &Config{
		Port:            port,
		JWTSecret:       jwtSecret,
		DataDir:         dataDir,
		ServerPublicURL: os.Getenv("SERVER_PUBLIC_URL"),
	}
}
