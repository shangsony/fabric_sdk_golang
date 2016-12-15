package api

import (
	"crypto/ecdsa"
	"encoding/pem"
	"errors"

	"github.com/fabric_sdk_golang/core/container"
	"github.com/fabric_sdk_golang/core/crypto/primitives"
	"github.com/fabric_sdk_golang/core/util"
	"github.com/fabric_sdk_golang/db"
	"github.com/fabric_sdk_golang/offical/decrypt"
	"github.com/fabric_sdk_golang/offical/encrypt"
	pb "github.com/fabric_sdk_golang/protos"
	"github.com/fabric_sdk_golang/utils"
	"github.com/golang/protobuf/proto"
	_ "github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
)

func (mb *memberImpl) Deploy(path string, args []string, metadata []byte, userid string) (*pb.Response, error) {
	logger.Info("deploy")
	var signKey *ecdsa.PrivateKey
	var rawCrt []byte
	var chainPk *ecdsa.PublicKey

	tcert, err := mb.getTcertsEx(userid, 20)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	signKey, err = utils.PrivStringToPointer(tcert.SK)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	block, _ := pem.Decode(tcert.Cert)
	if block == nil {
		logger.Fatal("pem.Decode return nil")
	}
	rawCrt = block.Bytes

	userInfo := &db.UsersInfo{}
	sqlDB := &db.SqlDB{}
	if sqlDB == nil {
		logger.Error("Null pointer deference")
		return nil, errors.New("Null pointer deference")
	}

	err = sqlDB.ReadUser(userInfo, userid)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	chainPk, err = utils.StringToPointerPubkey(userInfo.PkChain)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	spec := &pb.ChaincodeSpec{
		Type:        pb.ChaincodeSpec_GOLANG,
		ChaincodeID: &pb.ChaincodeID{Path: path},
		CtorMsg:     &pb.ChaincodeInput{util.ToChaincodeArgs(args...)},
	}

	codePackageBytes, err := container.GetChaincodePackageBytes(spec)
	if err != nil {
		logger.Error("Error getting chaincode package bytes", err)
		return nil, err
	}

	deploySpec := &pb.ChaincodeDeploymentSpec{
		ChaincodeSpec: spec,
		CodePackage:   codePackageBytes,
	}

	tx, err := pb.NewChaincodeDeployTransaction(deploySpec, spec.ChaincodeID.Name)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	tx.Metadata = metadata
	tx.Nonce, err = primitives.GetRandomNonce()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if viper.GetBool("security.privacy") {
		tx.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
		tx.ConfidentialityProtocolVersion = viper.GetString("security.confidentialityProtocolVersion")
		if err = encrypt.Process(tx, chainPk); err != nil {
			logger.Error(err)
			return nil, err
		}
	}

	tx.Cert = rawCrt

	rawTx, err := proto.Marshal(tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	rawSignature, err := primitives.ECDSASign(signKey, rawTx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	tx.Signature = rawSignature

	conn, peer, err := mb.getPeerClient()
	defer conn.Close()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	resp, err := peer.ProcessTransaction(context.Background(), tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	logger.Info("deploy resp", resp)
	return resp, nil
}

func (mb *memberImpl) Invoke(name string, args []string, txid string, metadata []byte, userid string) (*pb.Response, error) {
	logger.Info("invoke")

	var signKey *ecdsa.PrivateKey
	var rawCrt []byte
	var chainPk *ecdsa.PublicKey

	tcert, err := mb.getTcertsEx(userid, 20)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	signKey, err = utils.PrivStringToPointer(tcert.SK)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	block, _ := pem.Decode(tcert.Cert)
	if block == nil {
		logger.Fatal("pem.Decode return nil")
	}
	rawCrt = block.Bytes

	userInfo := &db.UsersInfo{}
	sqlDB := &db.SqlDB{}
	if sqlDB == nil {
		logger.Error("Null pointer deference")
		return nil, errors.New("Null pointer deference")
	}

	err = sqlDB.ReadUser(userInfo, userid)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	chainPk, err = utils.StringToPointerPubkey(userInfo.PkChain)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	spec := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			Type:        pb.ChaincodeSpec_GOLANG,
			ChaincodeID: &pb.ChaincodeID{Name: name},
			CtorMsg:     &pb.ChaincodeInput{util.ToChaincodeArgs(args...)},
		},
	}

	tx, err := pb.NewChaincodeExecute(spec, txid, pb.Transaction_CHAINCODE_INVOKE)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	tx.Metadata = metadata
	tx.Nonce, err = primitives.GetRandomNonce()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if viper.GetBool("security.privacy") {
		tx.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
		tx.ConfidentialityProtocolVersion = viper.GetString("security.confidentialityProtocolVersion")
		if err = encrypt.Process(tx, chainPk); err != nil {
			logger.Error(err)
			return nil, err
		}
	}
	tx.Cert = rawCrt

	rawTx, err := proto.Marshal(tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	rawSignature, err := primitives.ECDSASign(signKey, rawTx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	tx.Signature = rawSignature

	conn, peer, err := mb.getPeerClient()
	defer conn.Close()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	resp, err := peer.ProcessTransaction(context.Background(), tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	logger.Info("invoke resp", resp)
	return resp, nil
}

func (mb *memberImpl) Query(name string, args []string, txid string, metadata []byte, userid string) (*pb.Response, error) {
	logger.Info("query")
	var signKey *ecdsa.PrivateKey
	var rawCrt []byte
	var chainPk *ecdsa.PublicKey

	tcert, err := mb.getTcertsEx(userid, 20)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	signKey, err = utils.PrivStringToPointer(tcert.SK)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	block, _ := pem.Decode(tcert.Cert)
	if block == nil {
		logger.Fatal("pem.Decode return nil")
	}
	rawCrt = block.Bytes

	userInfo := &db.UsersInfo{}
	sqlDB := &db.SqlDB{}
	if sqlDB == nil {
		logger.Error("Null pointer deference")
		return nil, errors.New("Null pointer deference")
	}

	err = sqlDB.ReadUser(userInfo, userid)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	chainPk, err = utils.StringToPointerPubkey(userInfo.PkChain)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	spec := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			Type:        pb.ChaincodeSpec_GOLANG,
			ChaincodeID: &pb.ChaincodeID{Name: name},
			CtorMsg:     &pb.ChaincodeInput{util.ToChaincodeArgs(args...)},
		},
	}

	tx, err := pb.NewChaincodeExecute(spec, txid, pb.Transaction_CHAINCODE_QUERY)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	tx.Metadata = metadata
	tx.Nonce, err = primitives.GetRandomNonce()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if viper.GetBool("security.privacy") {
		tx.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
		tx.ConfidentialityProtocolVersion = viper.GetString("security.confidentialityProtocolVersion")
		if err = encrypt.Process(tx, chainPk); err != nil {
			logger.Error(err)
			return nil, err
		}
	}
	tx.Cert = rawCrt

	rawTx, err := proto.Marshal(tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	rawSignature, err := primitives.ECDSASign(signKey, rawTx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	tx.Signature = rawSignature

	conn, peer, err := mb.getPeerClient()
	defer conn.Close()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	resp, err := peer.ProcessTransaction(context.Background(), tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if viper.GetBool("security.privacy") {
		if resp.Status == pb.Response_FAILURE {
			logger.Error(string(resp.Msg))
			return nil, err
		}

		if resp.Msg, err = decrypt.DecryptQueryResult(tx, resp.Msg); nil != err {
			logger.Errorf("Failed decrypting query transaction result %s", string(resp.Msg[:]))
			return nil, err
		}
	}

	logger.Info("query resp", resp)
	return resp, nil
}
