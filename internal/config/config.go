package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type OpensearchConfig struct {
	Address  string
	Username string
	Password string
	Index    string
}

type Config struct {
	ServerPort       string
	OpensearchConfig OpensearchConfig
}

// LoadFromEnv читает конфигурацию из переменных окружения (и .env, если он есть).
// Все значения, кроме PORT, обязательны.
func LoadFromEnv() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		log.Println("[WARN] .env file not loaded:", err)
	}

	cfg := &Config{ServerPort: ":9100"}
	if port := os.Getenv("PORT"); port != "" {
		cfg.ServerPort = ":" + port
	}

	osCfg := OpensearchConfig{}
	var err error
	if osCfg.Address, err = required("OPENSEARCH_ADDR"); err != nil {
		return nil, err
	}
	if osCfg.Username, err = required("OPENSEARCH_USERNAME"); err != nil {
		return nil, err
	}
	if osCfg.Password, err = required("OPENSEARCH_PASSWORD"); err != nil {
		return nil, err
	}
	if osCfg.Index, err = required("OPENSEARCH_INDEX"); err != nil {
		return nil, err
	}

	cfg.OpensearchConfig = osCfg
	return cfg, nil
}

func required(key string) (string, error) {
	if v := os.Getenv(key); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no %s env", key)
}
