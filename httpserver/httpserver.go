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

	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/json"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/gin-gonic/contrib/ginrus"

	"github.com/waucka/radiant_prism/backend"
)

const (
	GoogleAuthRedirectPath = "/_googleauth"
)

type HttpServer struct {
	StaticFilesDir string
	TemplatesDir string
	BaseURL string
	Backend *backend.Backend
}

func csrFromPem(pemData []byte) (*x509.CertificateRequest, []byte, error) {
	csrBlock, remaining := pem.Decode(pemData)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, remaining, err
	}
	return csr, remaining, err
}

type AuthResult struct {
	ApiKeyId string `json:"api_key_id"`
	ApiKey string `json:"api_key"`
}

func (self *HttpServer) googleAuthCallback(c *gin.Context) {
	email, lifetime, err := self.Backend.CheckGoogleAuthState(
		c.Query("state"),
		c.Query("code"),
	)
	if err != nil {
		log.Error(err.Error())
		c.String(http.StatusInternalServerError, "Failed to fetch user info")
		return
	}

	apiKeyId, apiKey, err := self.Backend.CreateApiKey(email, lifetime)
	if err != nil {
		log.Error(err.Error())
		c.String(http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	if c.GetHeader("Accept") == "application/json" {
		c.JSON(http.StatusOK, &AuthResult{
			ApiKeyId: apiKeyId,
			ApiKey: apiKey,
		})
	} else {
		c.HTML(http.StatusOK, "authredirect.tmpl", gin.H{
			"ApiKeyId": apiKeyId,
			"ApiKey": apiKey,
		})
	}
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

	state, err := self.Backend.CreateGoogleAuthState(int(duration))
	if err != nil {
		log.Error(err.Error())
		c.String(http.StatusBadRequest, "Failed to store Google Auth state")
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, self.Backend.GetAuthCodeURL(state))
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
	sigOk, userPerms, err := self.Backend.ValidateSignature(apiKeyId, bodyBytes, reqSig)
	if err != nil {
		log.Error(err.Error())
		c.String(http.StatusBadRequest, fmt.Sprintf("Invalid API key ID: %s (or server error)", apiKeyId))
		return
	}
	if !sigOk {
		c.String(http.StatusBadRequest, "Invalid request signature")
		return
	}

	var provisionReq backend.ProvisionRequest
	err = json.Unmarshal(bodyBytes, &provisionReq)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	resp, berr := self.Backend.Provision(userPerms, &provisionReq)
	if berr != nil {
		if berr.Underlying != nil {
			log.WithFields(log.Fields{
				"remote_ip": c.ClientIP(),
			}).Infoln(berr.Underlying.Error())
		}
		log.WithFields(log.Fields{
			"remote_ip": c.ClientIP(),
		}).Infoln(berr.Error())
		c.String(berr.HttpCode(), berr.Error())
	}

	c.JSON(http.StatusOK, resp)
	log.WithFields(log.Fields{
		"remote_ip": c.ClientIP(),
	}).Infof("Provisioned client: %s", provisionReq.ClientName)
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

	asn1Cert, err := self.Backend.Renew(csr)

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: asn1Cert})

	c.Data(http.StatusOK, "application/octet-stream", pemCert)
	log.WithFields(log.Fields{
		"remote_ip": c.ClientIP(),
	}).Infof("Renewed certificate for client: %s", csr.Subject.CommonName)
}

func (self *HttpServer) v1Clients(c *gin.Context) {
	c.String(http.StatusInternalServerError, "Not implemented")
}

func (self *HttpServer) redirectRoot(c *gin.Context) {
	c.Redirect(http.StatusPermanentRedirect, self.BaseURL + "/webui")
}

func (self *HttpServer) webUI(c *gin.Context) {
	c.HTML(http.StatusOK, "main.tmpl", gin.H{
		"BaseURL": self.BaseURL,
	})
}

func (self *HttpServer) setupRoutes() *gin.Engine {
	r := gin.New()
	r.Use(ginrus.Ginrus(log.StandardLogger(), time.RFC3339, true))
	r.Use(gin.Recovery())

	r.LoadHTMLGlob(self.TemplatesDir + "/*.tmpl")

	r.GET(GoogleAuthRedirectPath, self.googleAuthCallback)
	r.Static("/static", self.StaticFilesDir)
	r.GET("/", self.redirectRoot)
	r.GET("/webui", self.webUI)

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
