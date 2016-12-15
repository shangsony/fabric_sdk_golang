package config

import (
	"testing"

	"github.com/spf13/viper"
)

func init() {
	InitCfg()
}

func TestConfig(t *testing.T) {
	logger.Debug("mbsrvc is value:", viper.Get("mbsrvc.address"))
	logger.Debug("rest is value:", viper.Get("sdkrest.port"))
	logger.Debug("driverName is value:", viper.Get("db.driverName"))
	logger.Debug("dataSourceName is value:", viper.Get("db.dataSourceName"))
	logger.Debug("driverName is value:", viper.Get("dbeca.driverName"))
	logger.Debug("dataSourceName is value:", viper.Get("dbeca.dataSourceName"))
	logger.Debug("log is value:", viper.Get("sdklogging.default"))
	logger.Debug("log is value:", viper.Get("sdklogging.rest"))
	logger.Debug("log is value:", viper.Get("sdklogging.db"))
	logger.Debug("log is value:", viper.Get("sdklogging.devops"))
	logger.Debug("log is value:", viper.GetBool("securitychain.privacy"))
}
