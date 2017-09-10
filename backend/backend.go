package backend

import (
	"fmt"
	"time"
	"errors"
	"net/http"
	"encoding/json"
	"database/sql"

	"math/big"
	"crypto/rand"
	"crypto/x509"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/pem"

	"github.com/go-redis/redis"
	"golang.org/x/oauth2"

	"github.com/waucka/radiant_prism/auth"
	"github.com/waucka/radiant_prism/certmgmt"
)

var (
	ErrBadPrivateKey = errors.New("Invalid private key type (must be RSA or ECDSA)")
)

type BackendErrorCode int

const (
	ErrForbidden BackendErrorCode = iota
	ErrNeedAuthentication
	ErrBadInputs
	ErrInternal
)

type BackendError struct {
	ErrorCode BackendErrorCode
	ErrorMessage string
	Underlying error
}

func wrapError(code BackendErrorCode, err error) *BackendError {
	return &BackendError{
		ErrorCode: code,
		ErrorMessage: err.Error(),
		Underlying: err,
	}
}

func (self *BackendError) Error() string {
	return self.ErrorMessage
}

func (self *BackendError) HttpCode() int {
	switch self.ErrorCode {
	case ErrForbidden:
		return http.StatusForbidden
	case ErrNeedAuthentication:
		return http.StatusUnauthorized
	case ErrBadInputs:
		return http.StatusBadRequest
	case ErrInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

type Backend struct {
	SqlConn *sql.DB
	RedisConn *redis.Client
	OAuthConfig *oauth2.Config
	CertMan *certmgmt.CertificateManager
}

func (self *Backend) CheckPermissions(apiKeyId string, object, verb string) (bool, error) {
	return auth.CheckPermissions(self.RedisConn, apiKeyId, object, verb)
}

func (self *Backend) CreateApiKey(username string, lifetime time.Duration) (string, string, error) {
	return auth.CreateApiKey(self.SqlConn, self.RedisConn, username, lifetime)
}

func (self *Backend) CreateGoogleAuthState(duration int) (string, error) {
	return auth.CreateGoogleAuthState(self.RedisConn, duration)
}

func (self *Backend) CheckGoogleAuthState(state, code string) (string, time.Duration, error) {
	return auth.CheckGoogleAuthState(self.RedisConn, self.OAuthConfig, state, code)
}

func (self *Backend) ValidateSignature(apiKeyId string, payload []byte, signature []byte) (bool, *auth.UserPermissions, error) {
	return auth.ValidateSignature(self.RedisConn, apiKeyId, payload, signature)
}

func (self *Backend) GetAuthCodeURL(state string) string {
	return self.OAuthConfig.AuthCodeURL(state)
}

type ProvisionRequest struct {
	UnixTime int64 `json:"unix_time"`
	ClientName string `json:"client_name"`
	KeyType string `json:"key_type"`
	KeyDetails json.RawMessage `json:"key_details"`
}

type ProvisionResponse struct {
	Certificate string `json:"certificate"`
	Key string `json:"key"`
}

func marshalPrivateKey(priv interface{}) ([]byte, error) {
	switch privKey := priv.(type) {
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(privKey)
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(privKey), nil
	default:
		return nil, ErrBadPrivateKey
	}
}

func getPrivateKeyPemBlockName(priv interface{}) (string, error) {
	switch priv.(type) {
	case *ecdsa.PrivateKey:
		return "EC PRIVATE KEY", nil
	case *rsa.PrivateKey:
		return "PRIVATE KEY", nil
	default:
		return "", ErrBadPrivateKey
	}
}

type EcdsaKeyDetails struct {
	Curve string `json:"curve"`
}

type RsaKeyDetails struct {
	Bits int `json:"bits"`
}

func createPrivateKey(keyType string, keyDetails json.RawMessage) (interface{}, error) {
	switch keyType {
	case "ecdsa":
		var ecdsaDetails EcdsaKeyDetails
		err := json.Unmarshal(keyDetails, &ecdsaDetails)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch ecdsaDetails.Curve {
		case "p256":
			curve = elliptic.P256()
		case "p384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("Invalid curve %s", ecdsaDetails.Curve)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "rsa":
		var rsaDetails RsaKeyDetails
		err := json.Unmarshal(keyDetails, &rsaDetails)
		if err != nil {
			return nil, err
		}
		return rsa.GenerateKey(rand.Reader, rsaDetails.Bits)
	default:
		return nil, fmt.Errorf("Invalid key type %s", keyType)
	}
}

func (self *Backend) Provision(userPerms *auth.UserPermissions, provisionReq *ProvisionRequest) (*ProvisionResponse, *BackendError) {
	if !userPerms.CanDo("provision", "client") {
		return nil, &BackendError{
			ErrorCode: ErrForbidden,
			ErrorMessage: "You are not permitted to provision clients",
		}
	}

	utcUnix := time.Now().UTC().Unix()
	timeSince := abs(utcUnix - provisionReq.UnixTime)
	if timeSince > 300 {
		return nil, &BackendError{
			ErrorCode: ErrBadInputs,
			ErrorMessage: "Too much time has passed since request was created",
		}
	}

	pk, err := createPrivateKey(provisionReq.KeyType, provisionReq.KeyDetails)
	if err != nil {
		return nil, &BackendError{
			ErrorCode: ErrInternal,
			ErrorMessage: fmt.Sprintf("Failed to create private key: %s", err.Error()),
			Underlying: err,
		}
	}

	asn1Cert, err := self.CertMan.CreateClientCert(pk, provisionReq.ClientName, big.NewInt(1))
	if err != nil {
		return nil, &BackendError{
			ErrorCode: ErrInternal,
			ErrorMessage: "Failed to sign client certificate",
			Underlying: err,
		}
	}

	asn1Key, err := marshalPrivateKey(pk)

	pkBlockName, err := getPrivateKeyPemBlockName(pk)
	if err != nil {
		return nil, &BackendError{
			ErrorCode: ErrInternal,
			ErrorMessage: "The impossible happened!",
			Underlying: err,
		}
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: asn1Cert})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: pkBlockName, Bytes: asn1Key})
	resp := &ProvisionResponse{
		Certificate: string(pemCert),
		Key: string(pemKey),
	}
	_, err = self.SqlConn.Exec(
		"INSERT INTO certs (client_name, cert_pem) VALUES ($1, $2)",
		provisionReq.ClientName,
		pemCert,
	)
	if err != nil {
		msg := fmt.Sprintf("Failed to store client cert: %s", err.Error())
		return nil, &BackendError{
			ErrorCode: ErrInternal,
			ErrorMessage: msg,
			Underlying: err,
		}
	}

	return resp, nil
}

func (self *Backend) Renew(csr *x509.CertificateRequest) ([]byte, *BackendError) {
	var certPem string
	err := self.SqlConn.QueryRow(
		"SELECT cert_pem FROM certs WHERE client_name = $1",
		csr.Subject.CommonName,
	).Scan(&certPem)
	if err != nil {
		return nil, &BackendError{
			ErrorCode: ErrInternal,
			ErrorMessage: "Failed to renew client certificate",
			Underlying: err,
		}
	}
	oldCert, _, err := certmgmt.CertFromPem([]byte(certPem))
	if err != nil {
		return nil, &BackendError{
			ErrorCode: ErrInternal,
			ErrorMessage: "Failed to retrieve old certificate",
			Underlying: err,
		}
	}

	err = certmgmt.CSRMatchesCert(csr, oldCert)
	if err != nil {
		msg := fmt.Sprintf("CSR does not match previously-issued certificate: %s", err.Error())
		return nil, &BackendError{
			ErrorCode: ErrBadInputs,
			ErrorMessage: msg,
			Underlying: err,
		}
	}

	// This API is among the most offensive I've seen in Go.
	serialNumber := big.NewInt(0)
	serialNumber.Add(oldCert.SerialNumber, big.NewInt(1))
	asn1Cert, err := self.CertMan.RenewCert(csr, serialNumber)
	if err != nil {
		return nil, &BackendError{
			ErrorCode: ErrInternal,
			ErrorMessage: "Failed to renew client certificate",
			Underlying: err,
		}
	}

	return asn1Cert, nil
}
