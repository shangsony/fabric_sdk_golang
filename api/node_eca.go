package api

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/fabric_sdk_golang/db"
	"github.com/fabric_sdk_golang/utils"
	"golang.org/x/net/context"

	pb "github.com/fabric_sdk_golang/ca/protos"
	"github.com/fabric_sdk_golang/core/crypto/primitives"
	"github.com/fabric_sdk_golang/core/crypto/primitives/ecies"
	"github.com/golang/protobuf/proto"
	google_protobuf "github.com/golang/protobuf/ptypes/timestamp"
	"google.golang.org/grpc"
)

var (
	// ECertSubjectRole is the ASN1 object identifier of the subject's role.
	ECertSubjectRole = asn1.ObjectIdentifier{2, 1, 3, 4, 5, 6, 7}
)

///获取ECAA客户端
func (mbsrvc *memberImpl) getECAAClient() (*grpc.ClientConn, pb.ECAAClient, error) {

	conn, err := getClientConn()
	if err != nil {
		logger.Errorf("Failed getting client connection: [%s]", err)
		return nil, nil, err
	}

	client := pb.NewECAAClient(conn)

	logger.Debug("Getting ECAA client...done")

	return conn, client, nil
}

///获取ECA客户端
func (mbsrvc *memberImpl) getECAClient() (*grpc.ClientConn, pb.ECAPClient, error) {

	conn, err := getClientConn()
	if err != nil {
		logger.Errorf("Failed getting client connection: [%s]", err)
		return nil, nil, err
	}

	client := pb.NewECAPClient(conn)

	logger.Debug("Getting ECA client...done")

	return conn, client, nil
}

//helper function for multiple tests
func (mbsrvc *memberImpl) Enroll(user *User) (interface{}, []byte, []byte, error) {
	conn, ecap, err := mbsrvc.getECAClient()
	if err != nil {
		logger.Error(err)
		return nil, nil, nil, err
	}
	defer conn.Close()
	logger.Debugf("连接正常")
	// Phase 1 of the protocol: Generate crypto material

	signPriv, err := primitives.NewECDSAKey()
	user.EnrollPrivKey = signPriv
	if err != nil {
		return nil, nil, nil, err
	}
	signPub, err := x509.MarshalPKIXPublicKey(&signPriv.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	encPriv, err := primitives.NewECDSAKey()
	if err != nil {
		return nil, nil, nil, err
	}
	encPub, err := x509.MarshalPKIXPublicKey(&encPriv.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	logger.Debug("x509.MarshalPKIXPublicKey(&encPriv.PublicKey)")
	req := &pb.ECertCreateReq{
		Ts:   &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
		Id:   &pb.Identity{Id: user.EnrollID},
		Tok:  &pb.Token{Tok: user.EnrollPwd},
		Sign: &pb.PublicKey{Type: pb.CryptoType_ECDSA, Key: signPub},
		Enc:  &pb.PublicKey{Type: pb.CryptoType_ECDSA, Key: encPub},
		Sig:  nil}
	logger.Debug("resp, err := ecap.CreateCertificatePair(context.Background(), req) start")
	resp, err := ecap.CreateCertificatePair(context.Background(), req)
	logger.Debug("resp, err := ecap.CreateCertificatePair(context.Background(), req)")
	if err != nil {
		return nil, nil, nil, err
	}

	//Phase 2 of the protocol
	spi := ecies.NewSPI()
	eciesKey, err := spi.NewPrivateKey(nil, encPriv)
	if err != nil {
		return nil, nil, nil, err
	}

	ecies, err := spi.NewAsymmetricCipherFromPublicKey(eciesKey)
	if err != nil {
		return nil, nil, nil, err
	}

	out, err := ecies.Process(resp.Tok.Tok)
	if err != nil {
		return nil, nil, nil, err
	}

	req.Tok.Tok = out
	req.Sig = nil

	hash := primitives.NewHash()
	raw, _ := proto.Marshal(req)
	hash.Write(raw)

	r, s, err := ecdsa.Sign(rand.Reader, signPriv, hash.Sum(nil))
	if err != nil {
		return nil, nil, nil, err
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}

	resp, err = ecap.CreateCertificatePair(context.Background(), req)
	if err != nil {
		return nil, nil, nil, err
	}

	// Verify we got valid crypto material back
	x509SignCert, err := primitives.DERToX509Certificate(resp.Certs.Sign)
	if err != nil {
		return nil, nil, nil, err
	}

	_, err = primitives.GetCriticalExtension(x509SignCert, ECertSubjectRole)
	if err != nil {
		return nil, nil, nil, err
	}

	x509EncCert, err := primitives.DERToX509Certificate(resp.Certs.Enc)
	if err != nil {
		return nil, nil, nil, err
	}

	_, err = primitives.GetCriticalExtension(x509EncCert, ECertSubjectRole)
	if err != nil {
		return nil, nil, nil, err
	}

	sqlex := &db.SqlDB{}
	if sqlex == nil {
		logger.Error("Null pointer deference")
		return nil, nil, nil, errors.New("Null pointer deference")
	}

	priv, err := utils.PrivToString(signPriv)
	if err != nil {
		logger.Error(err)
		return nil, nil, nil, err
	}

	strPkChain := string(resp.Pkchain)
	var userInfoTemp db.UsersInfo
	userInfoTemp.UserId = user.EnrollID
	userInfoTemp.Token = string(user.EnrollPwd)
	userInfoTemp.Priv = priv
	userInfoTemp.PkChain = strPkChain
	err = sqlex.ADDUser(&userInfoTemp)
	if err != nil {
		logger.Error(err)
		return nil, nil, nil, err
	}
	return signPriv, resp.Certs.Sign, resp.Pkchain, nil
}

func (mbsrvc *memberImpl) Registrar(registrar User, user *User) error {
	conn, ecaa, err := mbsrvc.getECAAClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	//create req
	req := &pb.RegisterUserReq{
		Id:   &pb.Identity{Id: user.EnrollID},
		Role: pb.Role(user.Role),
		//Account:     user.Affiliation,
		Affiliation: user.Affiliation,
		Registrar: &pb.Registrar{
			Id:            &pb.Identity{Id: registrar.EnrollID},
			Roles:         user.RegistrarRoles,
			DelegateRoles: user.RegistrarDelegateRoles,
		},
		Sig: nil}

	//sign the req
	hash := primitives.NewHash()
	raw, _ := proto.Marshal(req)
	hash.Write(raw)

	r, s, err := ecdsa.Sign(rand.Reader, registrar.EnrollPrivKey, hash.Sum(nil))
	if err != nil {
		msg := "Failed to register user. Error (ECDSA) signing request: " + err.Error()
		return errors.New(msg)
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}

	token, err := ecaa.RegisterUser(context.Background(), req)
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("Failed to obtain token")
	}

	//need the token for later tests
	user.EnrollPwd = token.Tok

	return nil
}
