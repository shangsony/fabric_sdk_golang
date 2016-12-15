package config

import (
	"strings"

	"github.com/fabric_sdk_golang/core/crypto/primitives"
	"github.com/spf13/viper"
)

func initViper() error {

	primitives.InitSecurityLevel("SHA3", 256)

	viper.SetEnvPrefix("app")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	// Conf
	viper.SetConfigName("api") // name of config file (without extension)
	viper.AddConfigPath(".")   // path to look for the config file in
	viper.SetConfigType("yaml")
	logger.Debug("api.yaml")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		logger.Errorf("viper.ReadInConfig error:%s", err)
		return err
	}
	return nil
}
