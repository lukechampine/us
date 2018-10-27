package main

import (
	"os"
	"os/user"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

var config struct {
	SiadAddr     string   `toml:"siad_addr"`
	SiadPassword string   `toml:"siad_password"`
	Contracts    string   `toml:"contracts"`
	MinShards    int      `toml:"min_shards"`
	Hosts        []string `toml:"hosts"`
	LogFile      string   `toml:"log_file"`
}

func loadConfig() error {
	// TODO: cross-platform location?
	user, err := user.Current()
	if err != nil {
		return err
	}
	_, err = toml.DecodeFile(filepath.Join(user.HomeDir, ".config", "us", "user.toml"), &config)
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
	if config.Contracts == "" {
		config.Contracts = filepath.Join(user.HomeDir, ".us", "contracts")
	}
	return nil
}
