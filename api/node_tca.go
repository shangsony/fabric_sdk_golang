package api

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/hmac"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"sort"
	"time"

	pb "github.com/fabric_sdk_golang/ca/protos"
	"github.com/fabric_sdk_golang/core/crypto/primitives"
	"github.com/fabric_sdk_golang/db"
	"github.com/fabric_sdk_golang/utils"
	"github.com/golang/protobuf/proto"
	google_protobuf "github.com/golang/protobuf/ptypes/timestamp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	TCertsStatic map[string]*list.List
)

type TCertBlock struct {
	Hash string
	SK   string
	Cert []byte
	Prk0 string
}

///获取TCA客户端
func (mbsrvc *memberImpl) getTCAClient() (*grpc.ClientConn, pb.TCAPClient, error) {

	conn, err := getClientConn()
	if err != nil {
		logger.Errorf("Failed getting client connection: [%s]", err)
	}

	client := pb.NewTCAPClient(conn)

	logger.Debug("Getting TCA client...done")

	return conn, client, nil
}

func (mbsrvc *memberImpl) callTCACreateCertificateSet(enrollPrivKey *ecdsa.PrivateKey, id string, attributes []string, num int) (*pb.TCertCreateSetResp, error) {
	conn, tcap, err := mbsrvc.getTCAClient()
	if err != nil {
		logger.Errorf("连接TCAClient出错，错误信息为:%s", err)
	}
	defer conn.Close()

	var attributesList []*pb.TCertAttribute
	for _, k := range attributes {
		tcertAttr := new(pb.TCertAttribute)
		tcertAttr.AttributeName = k
		attributesList = append(attributesList, tcertAttr)
	}

	// Execute the protocol
	now := time.Now()
	timestamp := google_protobuf.Timestamp{Seconds: int64(now.Second()), Nanos: int32(now.Nanosecond())}
	req := &pb.TCertCreateSetReq{
		Ts:         &timestamp,
		Id:         &pb.Identity{Id: id},
		Num:        uint32(num),
		Attributes: attributesList,
		Sig:        nil,
	}

	rawReq, err := proto.Marshal(req)
	if err != nil {
		logger.Errorf("Failed marshaling request [%s].", err.Error())
		return nil, err
	}

	// 2. Sign rawReq
	r, s, err := primitives.ECDSASignDirect(enrollPrivKey, rawReq) //client.ecdsaSignWithEnrollmentKey(rawReq)
	if err != nil {
		logger.Errorf("Failed creating signature for [% x]: [%s].", rawReq, err.Error())
		return nil, err
	}

	R, _ := r.MarshalText()
	S, _ := s.MarshalText()

	// 3. Append the signature
	req.Sig = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}

	// 4. Send request
	certSet, err := tcap.CreateCertificateSet(context.Background(), req)
	if err != nil {
		logger.Errorf("Failed requesting tca create certificate set [%s].", err.Error())
		return nil, err
	}
	return certSet, nil
}

//TODO check kdf value
func (mbsrvc *memberImpl) getTCertsFromTCA(enrollPrivKey *ecdsa.PrivateKey, id string, attrhash string, attributes []string, num int) (*list.List, error) {
	certSet, err := mbsrvc.callTCACreateCertificateSet(enrollPrivKey, id, attributes, num)
	if err != nil {
		return nil, err
	}
	TCertOwnerKDFKey := certSet.Certs.Key
	certDERs := certSet.Certs.Certs

	TCertOwnerEncryptKey := primitives.HMACAESTruncated(TCertOwnerKDFKey, []byte{1})
	ExpansionKey := primitives.HMAC(TCertOwnerKDFKey, []byte{2})

	listTecet := list.New()
	j := 0
	for i := 0; i < num; i++ {
		// DER to x509
		x509Cert, err := primitives.DERToX509Certificate(certDERs[i].Cert)
		prek0 := certDERs[i].Prek0
		if err != nil {
			logger.Debugf("Failed parsing certificate [% x]: [%s].", certDERs[i].Cert, err)

			continue
		}

		// Handle Critical Extenstion TCertEncTCertIndex
		tCertIndexCT, err := primitives.GetCriticalExtension(x509Cert, primitives.TCertEncTCertIndex)
		if err != nil {
			logger.Errorf("Failed getting extension TCERT_ENC_TCERTINDEX [% x]: [%s].", primitives.TCertEncTCertIndex, err)

			continue
		}

		//TODO ADD TCACERTPOOL
		// Verify certificate against root
		//if _, err := primitives.CheckCertAgainRoot(x509Cert, member.tcaCertPool); err != nil {
		//	logger.Warningf("Warning verifing certificate [%s].", err.Error())
		//
		//	continue
		//}

		// Verify public key

		// 384-bit ExpansionValue = HMAC(Expansion_Key, TCertIndex)
		// Let TCertIndex = Timestamp, RandValue, 1,2,…
		// Timestamp assigned, RandValue assigned and counter reinitialized to 1 per batch

		// Decrypt ct to TCertIndex (TODO: || EnrollPub_Key || EnrollID ?)
		pt, err := primitives.CBCPKCS7Decrypt(TCertOwnerEncryptKey, tCertIndexCT)
		if err != nil {
			logger.Errorf("Failed decrypting extension TCERT_ENC_TCERTINDEX [%s].", err.Error())

			continue
		}

		// Compute ExpansionValue based on TCertIndex
		TCertIndex := pt
		//		TCertIndex := []byte(strconv.Itoa(i))

		mac := hmac.New(primitives.NewHash, ExpansionKey)
		mac.Write(TCertIndex)
		ExpansionValue := mac.Sum(nil)

		// Derive tpk and tsk accordingly to ExpansionValue from enrollment pk,sk
		// Computable by TCA / Auditor: TCertPub_Key = EnrollPub_Key + ExpansionValue G
		// using elliptic curve point addition per NIST FIPS PUB 186-4- specified P-384

		// Compute temporary secret key
		tempSK := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: enrollPrivKey.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			},
			D: new(big.Int),
		}

		var k = new(big.Int).SetBytes(ExpansionValue)
		var one = new(big.Int).SetInt64(1)
		n := new(big.Int).Sub(enrollPrivKey.Params().N, one)
		k.Mod(k, n)
		k.Add(k, one)

		tempSK.D.Add(enrollPrivKey.D, k)
		tempSK.D.Mod(tempSK.D, enrollPrivKey.PublicKey.Params().N)

		// Compute temporary public key
		tempX, tempY := enrollPrivKey.PublicKey.ScalarBaseMult(k.Bytes())
		tempSK.PublicKey.X, tempSK.PublicKey.Y =
			tempSK.PublicKey.Add(
				enrollPrivKey.PublicKey.X, enrollPrivKey.PublicKey.Y,
				tempX, tempY,
			)

		// Verify temporary public key is a valid point on the reference curve
		isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
		if !isOn {
			logger.Error("Failed temporary public key IsOnCurve check.")

			continue
		}

		// Check that the derived public key is the same as the one in the certificate
		certPK := x509Cert.PublicKey.(*ecdsa.PublicKey)

		if certPK.X.Cmp(tempSK.PublicKey.X) != 0 {
			logger.Error("Derived public key is different on X")

			continue
		}

		if certPK.Y.Cmp(tempSK.PublicKey.Y) != 0 {
			logger.Error("Derived public key is different on Y")

			continue
		}

		// Verify the signing capability of tempSK
		err = primitives.VerifySignCapability(tempSK, x509Cert.PublicKey)
		if err != nil {
			logger.Errorf("Failed verifing signing capability [%s].", err.Error())

			continue
		}

		// Marshall certificate and secret key to be stored in the database
		if err != nil {
			logger.Errorf("Failed marshalling private key [%s].", err.Error())

			continue
		}

		if err := primitives.CheckCertPKAgainstSK(x509Cert, interface{}(tempSK)); err != nil {
			logger.Errorf("Failed checking TCA cert PK against private key [%s].", err.Error())

			continue
		}

		j++

		prek0Cp := make([]byte, len(prek0))
		copy(prek0Cp, prek0)
		tcertBlk := new(TCertBlock)
		sk, err := utils.PrivToString(tempSK)
		if err != nil {
			logger.Error(err.Error())
			return nil, err
		}
		certRaw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509Cert.Raw})
		prek0Temp := hex.EncodeToString(prek0Cp)
		tcertBlk.Hash = attrhash
		tcertBlk.SK = sk
		tcertBlk.Prk0 = prek0Temp
		tcertBlk.Cert = certRaw
		listTecet.PushBack(tcertBlk)
	}
	return listTecet, nil
}

//calculateAttributesHash generates a unique hash using the passed attributes.
func (mbsrvc *memberImpl) calculateAttributesHash(attributes []string) (attrHash string) {

	keys := make([]string, len(attributes))

	for _, k := range attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	values := make([]byte, len(keys))

	for _, k := range keys {
		vb := []byte(k)
		for _, bval := range vb {
			values = append(values, bval)
		}
	}
	attributesHash := primitives.Hash(values)
	return hex.EncodeToString(attributesHash)

}

func (mbsrvc *memberImpl) getTcerts(userName string, priv *ecdsa.PrivateKey, num int) (*list.List, error) {
	attributes := []string{"role"}
	attributeHash := mbsrvc.calculateAttributesHash(attributes)
	tCerts, err := mbsrvc.getTCertsFromTCA(priv, userName, attributeHash, attributes, num)
	if err != nil {
		return nil, err
	}
	return tCerts, nil
}

func (mbsrvc *memberImpl) getTcertsEx(userID string, num int) (*TCertBlock, error) {

	var tcertBlk *TCertBlock
	userInfo := &db.UsersInfo{}
	sqlDB := &db.SqlDB{}
	if sqlDB == nil {
		logger.Error("Null pointer deference")
		return nil, errors.New("Null pointer deference")
	}

	err := sqlDB.ReadUser(userInfo, userID)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	bFlag := false
	if listTemp, ok := TCertsStatic[userID]; ok {
		//存在
		if listTemp.Len() > 0 {
			tcert := listTemp.Front()
			listTemp.Remove(tcert)
			tcertBlk = tcert.Value.(*TCertBlock)
			return tcertBlk, nil
		} else {
			bFlag = true
		}

	} else {
		bFlag = true
	}

	if bFlag {
		priv, err := utils.PrivStringToPointer(userInfo.Priv)
		if priv == nil {
			logger.Error("Null pointer deference")
			return nil, errors.New("Null pointer deference")
		}

		if err != nil {
			logger.Errorf("PrivStringToPointer error:%s", err)
			return nil, err
		}
		listTcertNull, err := mbsrvc.getTcerts(userID, priv, num)
		if err != nil {
			logger.Errorf("mbsrvc.GetTcert error:%s", err)
			return nil, err
		}

		if listTcertNull.Len() > 0 {
			tcert := listTcertNull.Front()
			listTcertNull.Remove(tcert)
			tcertBlk = tcert.Value.(*TCertBlock)
			TCertsStatic[userID] = listTcertNull
			return tcertBlk, nil
		} else {
			return nil, errors.New("MB errors")
		}
	}

	return tcertBlk, nil
}
