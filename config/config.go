package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	APIURL   string      `mapstructure:"api_url"`
	Insecure bool        `mapstructure:"insecure"`
	Auth     AuthConfig  `mapstructure:"auth"`
	Indexer  IndexerConfig `mapstructure:"indexer"`
}

type AuthConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type IndexerConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

func Load() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	viper.AddConfigPath(filepath.Join(home, ".config", "wazuh-cli"))
	viper.AddConfigPath(".")

	viper.SetDefault("insecure", false)
	viper.SetDefault("auth.username", "wazuh")
	viper.SetDefault("indexer.username", "admin")

	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("cannot read config: %w", err)
		}
		// Missing config file is OK — "config init" can create it.
		return &Config{}, nil
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
