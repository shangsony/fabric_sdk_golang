package api

import (
	"container/list"
	"errors"
	"time"

	"github.com/fabric_sdk_golang/config"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var (
	logger = logging.MustGetLogger("golang")
)

func init() {
	config.InitCfg()
	TCertsStatic = make(map[string]*list.List)
}

///获取grpc连接
func getClientConn() (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	mbAddress := viper.GetString("mbsrvc.address")
	if mbAddress == "" {
		logger.Error("read mb address errors")
		return nil, errors.New("read mb address errors")
	}
	conn, err := grpc.Dial(mbAddress, opts...)
	if err != nil {
		logger.Error("grpc.Dial", err)
		return conn, err
	}
	logger.Debugf("conn mb:%s success！", mbAddress)
	return conn, nil
}

type memberImpl struct {
}
