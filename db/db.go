package db

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var (
	logger = logging.MustGetLogger("db")
)

type SqlDB struct {
}

///打开db
func (sqks *SqlDB) OpenDB() *sql.DB {
	driverName := viper.GetString("db.driverName")
	dataSourceName := viper.GetString("db.dataSourceName")
	bFlag := (driverName == "") || (dataSourceName == "")
	if bFlag {
		logger.Error("db conn args errors")
		return nil
	}

	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}
	return db
}
