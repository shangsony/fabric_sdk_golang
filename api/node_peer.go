package api

import (
	"time"

	pb "github.com/fabric_sdk_golang/protos"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

///获取grpc连接
func (mb *memberImpl) getClientConn() (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	peer := viper.GetString("peer.address")
	conn, err := grpc.Dial(peer, opts...)
	if err != nil {
		logger.Error("grpc.Dial", err)
		return conn, err
	}
	logger.Debugf("conn %s success ！", peer)
	return conn, nil
}

///获取Peer客户端
func (mb *memberImpl) getPeerClient() (*grpc.ClientConn, pb.PeerClient, error) {

	conn, err := mb.getClientConn()
	if err != nil {
		logger.Errorf("Failed getting client connection: [%s]", err)
	}

	client := pb.NewPeerClient(conn)

	logger.Debug("Getting Peer client...done")

	return conn, client, nil
}
