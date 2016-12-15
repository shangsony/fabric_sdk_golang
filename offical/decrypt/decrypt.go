package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"

	"github.com/fabric_sdk_golang/core/crypto/primitives"
	"github.com/fabric_sdk_golang/core/crypto/utils"
	"github.com/fabric_sdk_golang/ecies"
	pb "github.com/fabric_sdk_golang/protos"
	"github.com/op/go-logging"
)

var (
	logger = logging.MustGetLogger("offical decrypt")
	sk     *ecdsa.PrivateKey
)

const ( // sk of chain, for decrypt transaction

	chainKey = `-----BEGIN ECDSA PRIVATE KEY-----
MHcCAQEEIGPh4s6CzYtIWLMj9TdtrnHoUfJr3gQDU3O307SdTaZsoAoGCCqGSM49
AwEHoUQDQgAEliN7kTaC2P2GHsJZs/ZphlNKbQmHjCXOiPEaeRMkbfbr4c04R6Cl
9AYv5md1J4Xo+nbz/VX2Qtu7UDzwfDMQeQ==
-----END ECDSA PRIVATE KEY-----`
)

type chainCodeValidatorMessage1_2 struct {
	PrivateKey []byte
	StateKey   []byte
}

func init() {

	format := logging.MustStringFormatter(`[%{module}] %{time:2006-01-02 15:04:05} [%{level}] [%{longpkg} %{shortfile}] { %{message} }`)

	backendConsole := logging.NewLogBackend(os.Stderr, "", 0)
	backendConsole2Formatter := logging.NewBackendFormatter(backendConsole, format)

	logging.SetBackend(backendConsole2Formatter)

	block, _ := pem.Decode([]byte(chainKey))
	if block == nil {
		logger.Fatal("pem.Decode return nil")
	}

	var err error
	sk, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		logger.Fatal(err)
	}
}

func Process(tx *pb.Transaction) error {

	msgToValidatorsRaw, err := ecies.Decrypt(sk, tx.ToValidators)
	if err != nil {
		logger.Error(err)
		return err
	}

	msgToValidators := new(chainCodeValidatorMessage1_2)
	_, err = asn1.Unmarshal(msgToValidatorsRaw, msgToValidators)
	if err != nil {
		logger.Error(err)
		return err
	}

	priv, err := x509.ParseECPrivateKey(msgToValidators.PrivateKey)
	if err != nil {
		logger.Error(err)
		return err
	}

	payload, err := ecies.Decrypt(priv, tx.Payload)
	if err != nil {
		logger.Error(err)
		return err
	}
	tx.Payload = payload

	chaincodeID, err := ecies.Decrypt(priv, tx.ChaincodeID)
	if err != nil {
		logger.Error(err)
		return err
	}
	tx.ChaincodeID = chaincodeID

	if len(tx.Metadata) != 0 {
		metadata, err := ecies.Decrypt(priv, tx.Metadata)
		if err != nil {
			logger.Error(err)
			return err
		}
		tx.Metadata = metadata
	}

	return nil
}

func DecryptQueryResult(queryTx *pb.Transaction, ct []byte) ([]byte, error) {

	var queryKey []byte

	switch queryTx.ConfidentialityProtocolVersion {
	case "1.2":
		queryKey = primitives.HMACAESTruncated(nil, append([]byte{6}, queryTx.Nonce...))
	}

	if len(ct) <= primitives.NonceSize {
		return nil, utils.ErrDecrypt
	}

	c, err := aes.NewCipher(queryKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, ct)

	out, err := gcm.Open(nil, nonce, ct[gcm.NonceSize():], nil)
	if err != nil {
		logger.Errorf("Failed decrypting query result [%s].", err.Error())
		return nil, utils.ErrDecrypt
	}
	return out, nil
}
