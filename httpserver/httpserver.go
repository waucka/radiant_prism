package httpserver

// radiant_prism_server - Monitor (or perhaps spy on) Linux systems
// Copyright (C) 2017  Alexander Wauck
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import (
	"fmt"
	"time"
	"strconv"
	"io"
	"io/ioutil"
	"net/http"
	"errors"
	"database/sql"

	"math/big"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/pem"
	"encoding/json"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/gin-gonic/contrib/ginrus"
	"github.com/go-redis/redis"
	"golang.org/x/oauth2"

	"github.com/waucka/radiant_prism/auth"
)

const (
	GoogleAuthRedirectPath = "/_googleauth"
)

var (
	approvedClientKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment
	ErrBadPrivateKey = errors.New("Invalid private key type (must be RSA or ECDSA)")
	ErrInvalidCSRInternalSignature = errors.New("Invalid CSR internal signature")
	ErrMultipleCerts = errors.New("More than one certificate where one was expected")
	ErrCSRNotECDSA = errors.New("Public key in provided CSR is not ECDSA")
	ErrCSRNotRSA = errors.New("Public key in provided CSR is not RSA")
	ErrCSRDifferentKey = errors.New("Public key in provided CSR is different")
	ErrCSRBadKeyType = errors.New("Invalid public key type (must be RSA or ECDSA)")
	ErrCSRBadCommonName = errors.New("Common Name in provided CSR is different")
	Day = time.Hour * 24
	Year = Day * 365
)

type HttpServer struct {
	privateKey interface{}
	publicCert *x509.Certificate
	sqlConn *sql.DB
	redisConn *redis.Client
	oAuthConfig *oauth2.Config
}

func privKeyFromPem(pemData []byte) (interface{}, []byte, error) {
	keyBlock, remaining := pem.Decode(pemData)
	var key interface{}
	var err error
	key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, remaining, err
		}
	}
	return key, remaining, nil
}

func certFromPem(pemData []byte) (*x509.Certificate, []byte, error) {
	certBlock, remaining := pem.Decode(pemData)
	crt, err := x509.ParseCertificates(certBlock.Bytes)
	if err != nil {
		return nil, remaining, err
	}
	if len(crt) > 1 {
		return nil, remaining, ErrMultipleCerts
	}
	return crt[0], remaining, nil
}

func csrFromPem(pemData []byte) (*x509.CertificateRequest, []byte, error) {
	csrBlock, remaining := pem.Decode(pemData)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, remaining, err
	}
	return csr, remaining, err
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

type HttpServerConfig struct {
	PrivateKeyPath string
	PublicCertPath string
	SqlConn *sql.DB
	RedisConn *redis.Client
	OAuthConfig *oauth2.Config
}

func New(config HttpServerConfig) (*HttpServer, error) {
	privateKeyBytes, err := ioutil.ReadFile(config.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	privateKey, _, err := privKeyFromPem(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	publicCertBytes, err := ioutil.ReadFile(config.PublicCertPath)
	if err != nil {
		return nil, err
	}
	publicCert, _, err := certFromPem(publicCertBytes)
	if err != nil {
		return nil, err
	}

	return &HttpServer{
		privateKey: privateKey,
		publicCert: publicCert,
		sqlConn: config.SqlConn,
		redisConn: config.RedisConn,
		oAuthConfig: config.OAuthConfig,
	}, nil
}

func (self *HttpServer) certFromCsr(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	names := pkix.Name{
		CommonName: csr.Subject.CommonName,
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: names,
		NotBefore: now.Add(-10 * time.Minute).UTC(),
		NotAfter: now.Add(3 * Year).UTC(),
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey: csr.PublicKey,
		BasicConstraintsValid: true,
		IsCA: false,
		MaxPathLen: 0,
		MaxPathLenZero: false,
		KeyUsage: approvedClientKeyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
	}, nil
}

func (self *HttpServer) renewCert(csr *x509.CertificateRequest, serialNumber *big.Int) ([]byte, error) {
	if csr.CheckSignature() != nil {
		return nil, ErrInvalidCSRInternalSignature
	}

	clientCert, err := self.certFromCsr(csr)
	if err != nil {
		return nil, err
	}
	clientCert.SerialNumber = serialNumber

	return x509.CreateCertificate(rand.Reader, clientCert, self.publicCert, clientCert.PublicKey, self.privateKey)
}

func extractPublicKey(priv interface{}) interface{} {
	switch privKey := priv.(type) {
	case *ecdsa.PrivateKey:
		return privKey.Public()
	case *rsa.PrivateKey:
		return privKey.Public()
	default:
		return nil
	}
}

func (self *HttpServer) createClientCert(priv interface{}, clientName string, serialNumber *big.Int) ([]byte, error) {
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: clientName,
		},
		NotBefore: now.Add(-10 * time.Minute).UTC(),
		NotAfter: now.Add(3 * Year).UTC(),
		BasicConstraintsValid: true,
		IsCA: false,
		MaxPathLen: 0,
		MaxPathLenZero: false,
		KeyUsage: approvedClientKeyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
	}

	return x509.CreateCertificate(rand.Reader, template, self.publicCert, extractPublicKey(priv), self.privateKey)
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

type AuthResult struct {
	ApiKeyId string `json:"api_key_id"`
	ApiKey string `json:"api_key"`
}

func (self *HttpServer) googleAuthCallback(c *gin.Context) {
	email, lifetime, err := auth.CheckGoogleAuthState(
		self.redisConn,
		self.oAuthConfig,
		c.Query("state"),
		c.Query("code"),
	)
	if err != nil {
		log.Error(err.Error())
		c.String(http.StatusInternalServerError, "Failed to fetch user info")
		return
	}

	apiKeyId, apiKey, err := auth.CreateApiKey(self.sqlConn, self.redisConn, email, lifetime)
	if err != nil {
		log.Error(err.Error())
		c.String(http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	c.JSON(http.StatusOK, &AuthResult{
		ApiKeyId: apiKeyId,
		ApiKey: apiKey,
	})
}

// GET /v1/Authenticate
// Parameters:
//   duration: time in seconds that auth token should live for (min 300, max 21600)
func (self *HttpServer) v1Authenticate(c *gin.Context) {
	var duration int64
	var err error

	durationStr := c.Query("duration")
	if durationStr != "" {
		duration, err = strconv.ParseInt(durationStr, 10, 32)
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		if duration < 300 || duration < 21600 {
			c.String(http.StatusBadRequest, "duration out of range")
			return
		}
	} else {
		duration = 21600
	}

	state, err := auth.CreateGoogleAuthState(self.redisConn, int(duration))
	if err != nil {
		log.Error(err.Error())
		c.String(http.StatusBadRequest, "Failed to store Google Auth state")
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, self.oAuthConfig.AuthCodeURL(state))
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

// POST /v1/provision
// Body content type: application/json
// Body contents:
// {
//     "unix_time": 1234567890,
//     "client_name": "foobar",
//     "key_type": "ecdsa",
//     "key_details": {
//       "curve": "p256"
//     }
// }
func (self *HttpServer) v1Provision(c *gin.Context) {
	r := c.Request
	if r.Body == nil {
		log.Errorln("No body!")
		c.String(http.StatusBadRequest, "No body")
		return
	}
	defer r.Body.Close()
	// 1K is probably overly generous, but whatever.
	lr := &io.LimitedReader{R: r.Body, N: 1024}
	bodyBytes, err := ioutil.ReadAll(lr)
	if err != nil {
		log.Errorln(err.Error())
		// Returning anything is probably futile, since the
		// connection probably died.  Let's try anyway!
		c.String(http.StatusBadRequest, "Failed to read body")
		return
	}

	reqSigStr := r.Header.Get("Request-Signature")
	if reqSigStr == "" {
		log.Errorln("No request signature")
		c.String(http.StatusBadRequest, "No request signature")
		return
	}

	reqSig, err := base64.StdEncoding.DecodeString(reqSigStr)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "Invalid request signature")
		return
	}

	apiKeyId := r.Header.Get("Prism-Api-Key-Id")
	sigOk, userPerms, err := auth.ValidateSignature(self.redisConn, apiKeyId, bodyBytes, reqSig)
	if err != nil {
		log.Error(err.Error())
		c.String(http.StatusBadRequest, fmt.Sprintf("Invalid API key ID: %s (or server error)", apiKeyId))
		return
	}
	if !sigOk {
		c.String(http.StatusBadRequest, "Invalid request signature")
		return
	}

	if !userPerms.CanDo("provision", "client") {
		c.String(http.StatusForbidden, "You are not permitted to provision clients")
		return
	}

	var provisionReq ProvisionRequest
	err = json.Unmarshal(bodyBytes, &provisionReq)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "Invalid body")
		return
	}

	utcUnix := time.Now().UTC().Unix()
	log.Debugf("UTC Unix timestamp: %d", utcUnix)
	timeSince := abs(utcUnix - provisionReq.UnixTime)
	if timeSince > 300 {
		msg := fmt.Sprintf(
			"Too much time (%d seconds) has elapsed since request was sent",
			timeSince,
		)
		log.Errorln(msg)
		c.String(http.StatusBadRequest, msg)
		return
	}

	pk, err := createPrivateKey(provisionReq.KeyType, provisionReq.KeyDetails)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, fmt.Sprintf("Failed to create private key: %s", err.Error()))
		return
	}

	asn1Cert, err := self.createClientCert(pk, provisionReq.ClientName, big.NewInt(1))
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusInternalServerError, "Failed to sign client certificate")
		return
	}

	asn1Key, err := marshalPrivateKey(pk)

	pkBlockName, err := getPrivateKeyPemBlockName(pk)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusInternalServerError, "The impossible happened!")
		return
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: asn1Cert})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: pkBlockName, Bytes: asn1Key})
	resp := ProvisionResponse{
		Certificate: string(pemCert),
		Key: string(pemKey),
	}
	_, err = self.sqlConn.Exec(
		"INSERT INTO certs (client_name, cert_pem) VALUES ($1, $2)",
		provisionReq.ClientName,
		pemCert,
	)
	if err != nil {
		msg := fmt.Sprintf("Failed to store client cert: %s", err.Error())
		log.WithFields(log.Fields{
			"remote_ip": c.ClientIP(),
		}).Infoln(msg)
		c.String(http.StatusInternalServerError, msg)
		return
	}

	c.JSON(http.StatusOK, resp)
	log.WithFields(log.Fields{
		"remote_ip": c.ClientIP(),
	}).Infof("Provisioned client: %s", provisionReq.ClientName)
}

func csrMatchesCert(csr *x509.CertificateRequest, oldCert *x509.Certificate) error {
	switch oldPubKey := oldCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		newPubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrCSRNotECDSA
		}

		if oldPubKey.X.Cmp(newPubKey.X) != 0 || oldPubKey.Y.Cmp(newPubKey.Y) != 0 {
			return ErrCSRDifferentKey
		}

		oldParams := oldPubKey.Params()
		newParams := newPubKey.Params()
		if oldParams.P.Cmp(newParams.P) != 0 ||
			oldParams.N.Cmp(newParams.N) != 0 ||
			oldParams.B.Cmp(newParams.B) != 0 ||
			oldParams.Gx.Cmp(newParams.Gx) != 0 ||
			oldParams.Gy.Cmp(newParams.Gy) != 0 ||
			oldParams.BitSize != newParams.BitSize {
			return ErrCSRDifferentKey
		}
	case *rsa.PublicKey:
		newPubKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return ErrCSRNotRSA
		}

		if oldPubKey.N.Cmp(newPubKey.N) != 0 || oldPubKey.E != newPubKey.E {
			return ErrCSRDifferentKey
		}
	default:
		return ErrCSRBadKeyType
	}

	if csr.Subject.CommonName != oldCert.Subject.CommonName {
		return ErrCSRBadCommonName
	}

	return nil
}

func (self *HttpServer) v1Renew(c *gin.Context) {
	r := c.Request
	if r.Body == nil {
		log.Errorln("No CSR!")
		c.String(http.StatusBadRequest, "No CSR")
		return
	}
	defer r.Body.Close()
	// 8K is probably overly generous.
	lr := &io.LimitedReader{R: r.Body, N: 8 * 1024}
	bodyBytes, err := ioutil.ReadAll(lr)
	if err != nil {
		log.Errorln(err.Error())
		// Returning anything is probably futile, since the
		// connection probably died.  Let's try anyway!
		c.String(http.StatusBadRequest, "Failed to read CSR")
		return
	}

	csr, _, err := csrFromPem(bodyBytes)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "Malformed CSR")
		return
	}

	var certPem string
	err = self.sqlConn.QueryRow(
		"SELECT cert_pem FROM certs WHERE client_name = $1",
		csr.Subject.CommonName,
	).Scan(&certPem)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusInternalServerError, "Failed to renew client certificate")
		return
	}
	oldCert, _, err := certFromPem([]byte(certPem))
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusInternalServerError, "Failed to retrieve old certificate")
		return
	}

	// This API is among the most offensive I've seen in Go.
	serialNumber := big.NewInt(0)
	serialNumber.Add(oldCert.SerialNumber, big.NewInt(1))
	asn1Cert, err := self.renewCert(csr, serialNumber)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusInternalServerError, "Failed to renew client certificate")
		return
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: asn1Cert})

	c.Data(http.StatusOK, "application/octet-stream", pemCert)
	log.WithFields(log.Fields{
		"remote_ip": c.ClientIP(),
	}).Infof("Renewed certificate for client: %s", csr.Subject.CommonName)
}

func (self *HttpServer) v1Clients(c *gin.Context) {
	c.String(http.StatusInternalServerError, "Not implemented")
}

func (self *HttpServer) setupRoutes() *gin.Engine {
	r := gin.New()
	r.Use(ginrus.Ginrus(log.StandardLogger(), time.RFC3339, true))
	r.Use(gin.Recovery())
	r.GET(GoogleAuthRedirectPath, self.googleAuthCallback)

	v1 := r.Group("/v1")
	v1.GET("/authenticate", self.v1Authenticate)
	v1.PUT("/provision", self.v1Provision)
	v1.PUT("/renew", self.v1Renew)
	v1.GET("/clients", self.v1Clients)

	return r
}

func (self *HttpServer) RunTLS(listenPort int, certFile string, keyFile string) {
	r := self.setupRoutes()
	log.Infof("HTTPS server is running on port %d", listenPort)
	r.RunTLS(fmt.Sprintf(":%d", listenPort), certFile, keyFile)
}

func (self *HttpServer) Run(listenPort int) {
	r := self.setupRoutes()
	log.Infof("HTTP server is running on port %d", listenPort)
	r.Run(fmt.Sprintf(":%d", listenPort))
}
