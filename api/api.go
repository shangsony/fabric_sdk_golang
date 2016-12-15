package api

import (
	"crypto/ecdsa"

	pb "github.com/fabric_sdk_golang/protos"
)

type User struct {
	EnrollID               string
	EnrollPwd              []byte
	EnrollPrivKey          *ecdsa.PrivateKey
	Role                   int
	Affiliation            string
	RegistrarRoles         []string
	RegistrarDelegateRoles []string
}

type Member interface {
	Registrar(registrar User, user *User) error
	Enroll(user *User) (interface{}, []byte, []byte, error)
	Deploy(path string, args []string, metadata []byte, userid string) (*pb.Response, error)
	Invoke(name string, args []string, txid string, metadata []byte, userid string) (*pb.Response, error)
	Query(name string, args []string, txid string, metadata []byte, userid string) (*pb.Response, error)
	Network() (string, error)
	GetBlocks(id string) (string, error)
	GetChain() (string, error)
	GetTransactions(txid string) (string, error)
}

func InitMbImpl() Member {
	mbImpl := &memberImpl{}
	return mbImpl
}
