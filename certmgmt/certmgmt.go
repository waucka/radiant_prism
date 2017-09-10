package certmgmt

import (
	"time"
	"errors"
	"io/ioutil"

	"math/big"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rsa"
	"crypto/ecdsa"
	"encoding/pem"
)

var (
	ApprovedClientKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment
	StandardClientCertLifetime time.Duration = 3 * Year

	Day = time.Hour * 24
	Year = Day * 365

	ErrInvalidCSRInternalSignature = errors.New("Invalid CSR internal signature")
	ErrMultipleCerts = errors.New("More than one certificate where one was expected")
	ErrCSRNotECDSA = errors.New("Public key in provided CSR is not ECDSA")
	ErrCSRNotRSA = errors.New("Public key in provided CSR is not RSA")
	ErrCSRDifferentKey = errors.New("Public key in provided CSR is different")
	ErrCSRBadKeyType = errors.New("Invalid public key type (must be RSA or ECDSA)")
	ErrCSRBadCommonName = errors.New("Common Name in provided CSR is different")
)

func PrivKeyFromPem(pemData []byte) (interface{}, []byte, error) {
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

func CertFromPem(pemData []byte) (*x509.Certificate, []byte, error) {
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

type CertificateManager struct {
	publicCert *x509.Certificate
	privateKey interface{}
}

func New(publicCert *x509.Certificate, privateKey interface{}) *CertificateManager {
	return &CertificateManager{
		publicCert: publicCert,
		privateKey: privateKey,
	}
}

func NewFromPaths(publicCertPath, privateKeyPath string) (*CertificateManager, error) {
	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	privateKey, _, err := PrivKeyFromPem(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	publicCertBytes, err := ioutil.ReadFile(publicCertPath)
	if err != nil {
		return nil, err
	}
	publicCert, _, err := CertFromPem(publicCertBytes)
	if err != nil {
		return nil, err
	}

	return &CertificateManager{
		publicCert: publicCert,
		privateKey: privateKey,
	}, nil
}

func (self *CertificateManager) CreateClientCert(priv interface{}, clientName string, serialNumber *big.Int) ([]byte, error) {
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: clientName,
		},
		NotBefore: now.Add(-10 * time.Minute).UTC(),
		NotAfter: now.Add(StandardClientCertLifetime).UTC(),
		BasicConstraintsValid: true,
		IsCA: false,
		MaxPathLen: 0,
		MaxPathLenZero: false,
		KeyUsage: ApprovedClientKeyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
	}

	return x509.CreateCertificate(rand.Reader, template, self.publicCert, extractPublicKey(priv), self.privateKey)
}

func (self *CertificateManager) RenewCert(csr *x509.CertificateRequest, serialNumber *big.Int) ([]byte, error) {
	if csr.CheckSignature() != nil {
		return nil, ErrInvalidCSRInternalSignature
	}

	clientCert, err := certFromCsr(csr)
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

func certFromCsr(csr *x509.CertificateRequest) (*x509.Certificate, error) {
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
		KeyUsage: ApprovedClientKeyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
	}, nil
}

func CSRMatchesCert(csr *x509.CertificateRequest, oldCert *x509.Certificate) error {
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
