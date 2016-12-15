package config

import (
	"os"

	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var (
	logger   = logging.MustGetLogger("config")
	logLevel = make(map[string]logging.Level, 7)
)

func initLoging() {
	logLevel["critical"] = logging.CRITICAL
	logLevel["error"] = logging.ERROR
	logLevel["warning"] = logging.WARNING
	logLevel["notice"] = logging.NOTICE
	logLevel["info"] = logging.INFO
	logLevel["debug"] = logging.DEBUG

	format := logging.MustStringFormatter(`[%{module}] %{time:2006-01-02 15:04:05} [%{level}] [%{longpkg} %{shortfile}] { %{message} }`)

	backendConsole := logging.NewLogBackend(os.Stderr, "", 0)
	backendConsole2Formatter := logging.NewBackendFormatter(backendConsole, format)

	logging.SetBackend(backendConsole2Formatter)
}

func initlogLevel() {
	for key, value := range viper.GetStringMap("sdklogging") {
		if level, ok := logLevel[value.(string)]; !ok {
			logger.Fatal(key, value, "is illegal")
		} else {
			if key == "default" {
				logging.SetLevel(level, "")
			} else {
				logging.SetLevel(level, key)
			}
		}
	}
}
