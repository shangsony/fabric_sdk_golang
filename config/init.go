package config

import (
	_ "github.com/fabric_sdk_golang/core/crypto"
)

func InitCfg() error {
	initLoging()
	err := initViper()
	if err != nil {
		return nil
	}
	initlogLevel()
	return nil
}
