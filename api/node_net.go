package api

import (
	"github.com/fabric_sdk_golang/utils"
	"github.com/spf13/viper"
)

func (mbsrvc *memberImpl) gethost() (string, error) {
	var strNets []string
	strNets = append(strNets, viper.GetString("rest.net1"), viper.GetString("rest.net2"), viper.GetString("rest.net3"), viper.GetString("rest.net4"))
	var strConn string
	for _, r := range strNets {
		conn := &utils.Clienter{}
		if conn.Connect(r) == true {
			strConn = r
			break
		}
	}
	return strConn, nil
}

func (mbsrvc *memberImpl) Network() (string, error) {
	strConn, err := mbsrvc.gethost()
	if err != nil {
		logger.Error()
		return "", err
	}
	strConn = "http://" + strConn + "/network/peers"
	resp, err := utils.HttpClientGET(strConn)
	if err != nil {
		logger.Error(err)
	}
	return resp, err
}

func (mbsrvc *memberImpl) GetBlocks(id string) (string, error) {
	strConn, err := mbsrvc.gethost()
	if err != nil {
		logger.Error()
		return "", err
	}
	strConn = "http://" + strConn + "/chain/blocks/" + id
	resp, err := utils.HttpClientGET(strConn)
	if err != nil {
		logger.Error(err)
	}
	return resp, err
}

func (mbsrvc *memberImpl) GetChain() (string, error) {
	strConn, err := mbsrvc.gethost()
	if err != nil {
		logger.Error()
		return "", err
	}
	strConn = "http://" + strConn + "/chain"
	resp, err := utils.HttpClientGET(strConn)
	if err != nil {
		logger.Error(err)
	}
	return resp, err
}

func (mbsrvc *memberImpl) GetTransactions(txid string) (string, error) {
	strConn, err := mbsrvc.gethost()
	if err != nil {
		logger.Error()
		return "", err
	}
	strConn = "http://" + strConn + "/transactions/" + txid
	resp, err := utils.HttpClientGET(strConn)
	if err != nil {
		logger.Error(err)
	}
	return resp, err
}
