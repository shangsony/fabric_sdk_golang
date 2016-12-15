package utils

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"errors"

	"github.com/fabric_sdk_golang/core/crypto/primitives"
	"github.com/op/go-logging"
)

var (
	logger = logging.MustGetLogger("utils")
)

///将私钥转换为字符串
func PrivToString(priv *ecdsa.PrivateKey) (string, error) {
	keyRaw, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	byPriv := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: keyRaw})
	return string(byPriv), err
}

///将字符串的私钥转换为指针
func PrivStringToPointer(strPriv string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strPriv))
	if block == nil {
		return nil, nil
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return priv, err
	}
	return priv, err
}

///将公钥从byte转换成字符串
func ByteToStringPubkey(chainKeyPem []byte) (string, error) {
	chainKeyPub, err := primitives.PEMtoPublicKey(chainKeyPem, nil)
	if err != nil {
		logger.Error(err)
		return "", err
	}
	chainKeyRaw, err := primitives.PublicKeyToPEM(chainKeyPub, nil)
	if err != nil {
		logger.Error(err)
		return "", err
	}
	chainKey := string(chainKeyRaw)
	return chainKey, nil
}

///将公钥从字符串转换为指针
func StringToPointerPubkey(strPubkey string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strPubkey))
	if block == nil {
		logger.Error("pem.Decode return nil")
		return nil, errors.New("pem.Decode return nil")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	var ok bool
	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		logger.Error("chainKey is not in format of ecdsa")
		return nil, errors.New("chainKey is not in format of ecdsa")
	}
	return pk, nil
}
