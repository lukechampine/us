package main

import (
	"os"
	"os/user"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

var config struct {
	SiadAddr           string `toml:"siad_addr"`
	SiadPassword       string `toml:"siad_password"`
	SHARDAddr          string `toml:"shard_addr"`
	ContractsAvailable string `toml:"contracts_available"`
	ContractsEnabled   string `toml:"contracts_enabled"`
	MinShards          int    `toml:"min_shards"`
}

func loadConfig() error {
	// TODO: cross-platform location?
	user, err := user.Current()
	if err != nil {
		return err
	}
	defaultDir := filepath.Join(user.HomeDir, ".config", "us")
	_, err = toml.DecodeFile(filepath.Join(defaultDir, "user.toml"), &config)
	if os.IsNotExist(err) {
		// if no config file found, proceed with empty config
		err = nil
	}
	if err != nil {
		return err
	}
	// set defaults
	if config.SiadAddr == "" {
		config.SiadAddr = "localhost:9980"
	}
	if config.ContractsAvailable == "" {
		config.ContractsAvailable = filepath.Join(defaultDir, "contracts-available")
	}
	if config.ContractsEnabled == "" {
		config.ContractsEnabled = filepath.Join(defaultDir, "contracts-enabled")
	}
	return nil
}
