package api

import (
	_ "crypto/ecdsa"
	"testing"

	"github.com/fabric_sdk_golang/config"
)

var testAdmin = User{EnrollID: "admin", EnrollPwd: []byte("Xurw3yU9zI0l")}
var testUser = User{EnrollID: "testUser", Role: 1, Affiliation: "institution_a"}

//func TestEnroll(t *testing.T) {
//	config.InitCfg()
//	mbsrvc := &memberImpl{}
//	priv, _, _, err := mbsrvc.Enroll(&testAdmin)
//	testAdmin.EnrollPrivKey = priv.(*ecdsa.PrivateKey)
//	if err != nil {
//		t.Log(err)
//	}
//	t.Log("登录成功")
//	mbsrvc.Registrar(testAdmin, &testUser)
//	t.Log(testUser)
//}

//func TestDeploy(t *testing.T) {
//	mbsrvc := &memberImpl{}
//	path := "github.com/fabric_sdk_golang/chaincodecc"
//	args := []string{"init"}
//	mbsrvc.Deploy(path, args, []byte("dummy metadata"), "admin")
//}

func TestInvoke(t *testing.T) {
	config.InitCfg()
	t.Log("invoke")
	mbsrvc := &memberImpl{}
	path := "662d8d0c4dcca29101fdc38712cb246a750c080c7ffe0e832a59d21c7d413361050428af104b4bb48c0776a6f7f47cf9d2db5d8f7a4b5efd9514733affdd3df0"
	args := []string{"invoke", "Pt999", "7.7g"}

	msg, err := mbsrvc.Invoke(path, args, "4250d938490999459f4567cd58", []byte("dummy metadata"), "admin")
	t.Log(msg)
	t.Log(err)
}

func TestQuery(t *testing.T) {
	t.Log("query")
	mbsrvc := &memberImpl{}
	path := "662d8d0c4dcca29101fdc38712cb246a750c080c7ffe0e832a59d21c7d413361050428af104b4bb48c0776a6f7f47cf9d2db5d8f7a4b5efd9514733affdd3df0"
	args := []string{"query", "Pt999"}

	msg, err := mbsrvc.Query(path, args, "4250d938490999459f4567cd59", []byte("dummy metadata"), "admin")
	t.Log(string(msg.Msg))
	t.Log(err)
}

func TestNetWork(t *testing.T) {
	config.InitCfg()
	mbsrvc := &memberImpl{}
	resp, err := mbsrvc.Network()
	if err != nil {
		t.Log(err)
	}
	t.Log(resp)
}

func TestGetChain(t *testing.T) {
	config.InitCfg()
	mbsrvc := &memberImpl{}
	resp, err := mbsrvc.GetChain()
	if err != nil {
		t.Log(err)
	}
	t.Log(resp)
}

func TestGetBlocks(t *testing.T) {
	config.InitCfg()
	mbsrvc := &memberImpl{}
	resp, err := mbsrvc.GetBlocks("2")
	if err != nil {
		t.Log(err)
	}
	t.Log(resp)
}

func TestGetTransactions(t *testing.T) {
	config.InitCfg()
	mbsrvc := &memberImpl{}
	resp, err := mbsrvc.GetTransactions("4250d938490999459f4567cd58")
	if err != nil {
		t.Log(err)
	}
	t.Log(resp)
}
