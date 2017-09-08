package auth

import (
	"fmt"
	"time"
	"io/ioutil"
	"net/http"
	"database/sql"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"golang.org/x/oauth2"

	"github.com/go-redis/redis"
)

var (
	AllPermissions = OVRecords{
		"client": VerbSet{
			"provision": true,
			"edit": true,
			"delete": true,
			"view": true,
			"list": true,
		},
	}
)

func randomBase64(bytes int) string{
	b := make([]byte, bytes)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func computeHmac(apiKey, data []byte) []byte {
	h := hmac.New(sha256.New, apiKey)
	h.Write(data)
	return h.Sum(nil)
}

func ValidateSignature(redisConn *redis.Client, apiKeyId string, payload []byte, signature []byte) (bool, *UserPermissions, error) {
	permsJson, err := redisConn.Get(fmt.Sprintf("apikeys:%s", apiKeyId)).Bytes()
	if err != nil {
		return false, nil, err
	}

	var userPerms UserPermissions
	err = json.Unmarshal(permsJson, &userPerms)
	if err != nil {
		return false, nil, err
	}

	apiKeyBytes, err := base64.StdEncoding.DecodeString(userPerms.ApiKey)
	if err != nil {
		return false, &userPerms, err
	}

	hmacSig := computeHmac(apiKeyBytes, payload)
	return hmac.Equal(hmacSig, signature), &userPerms, nil
}

type VerbSet map[string]bool
type OVRecords map[string]VerbSet

func getPermissions(sqlConn *sql.DB, username string) (OVRecords, error) {
	permissions := make(OVRecords)
	rows, err := sqlConn.Query(
		"SELECT object, verb FROM permissions WHERE subject = $1",
		username,
	)
	if err != nil {
		return permissions, err
	}

	defer rows.Close()
	for rows.Next() {
		var object, verb string
		if err := rows.Scan(&object, verb); err != nil {
			return permissions, err
		}
		verbs, ok := permissions[object]
		if !ok {
			verbs = make(map[string]bool, 0)
			permissions[object] = verbs
		}
		verbs[verb] = true
	}
	err = rows.Err()
	return permissions, err
}

type UserPermissions struct {
	ApiKey string `json:"api_key"`
	IsAdmin bool `json:"is_admin"`
	Permissions OVRecords `json:"permissions"`
}

func (self *UserPermissions) CanDo(verb, object string) bool {
	if self.IsAdmin {
		return true
	}

	verbs, ok := self.Permissions[object]
	if !ok {
		return false
	}
	_, ok = verbs[verb]
	return ok
}

func CheckPermissions(redisConn *redis.Client, apiKeyId string, object, verb string) (bool, error) {
	permsJson, err := redisConn.Get(fmt.Sprintf("apikeys:%s", apiKeyId)).Bytes()
	if err != nil {
		return false, err
	}

	var perms UserPermissions
	err = json.Unmarshal(permsJson, &perms)
	if err != nil {
		return false, err
	}

	verbs, ok := perms.Permissions[object]
	if !ok {
		return false, nil
	}

	_, ok = verbs[verb]

	return ok, nil
}

func CreateApiKey(sqlConn *sql.DB, redisConn *redis.Client, username string, lifetime time.Duration) (string, string, error) {
	permissions, err := getPermissions(sqlConn, username)
	if err != nil {
		return "", "", err
	}

	// Seriously, WTF?
	var usernameUseless string
	err = sqlConn.QueryRow(
		"SELECT username FROM admins WHERE username = $1",
		username,
	).Scan(&usernameUseless)
	isAdmin := err == nil

	apiKeyId := randomBase64(8)
	apiKey := randomBase64(32)

	permsJsonBytes, err := json.Marshal(&UserPermissions{
		ApiKey: apiKey,
		IsAdmin: isAdmin,
		Permissions: permissions,
	})
	if err != nil {
		return "", "", err
	}

	_, err = redisConn.Set(fmt.Sprintf("apiKeys:%s", apiKeyId), permsJsonBytes, lifetime).Result()
	if err != nil {
		return "", "", err
	}

	return apiKeyId, apiKey, nil
}

type GoogleAuthState struct {
	Version int `json:"version"`
	Duration int `json:"duration"`
}

func CreateGoogleAuthState(redisConn *redis.Client, duration int) (string, error) {
	state := randomBase64(32)

	stateJsonBytes, err := json.Marshal(&GoogleAuthState{
		Version: 1,
		Duration: duration,
	})
	if err != nil {
		return "", err
	}

	_, err = redisConn.Set(fmt.Sprintf("googleauthstate:%s", state), stateJsonBytes, time.Minute).Result()
	return state, err
}

func CheckGoogleAuthState(redisConn *redis.Client, oAuthConfig *oauth2.Config, state, code string) (string, time.Duration, error) {
	stateJsonBytes, err := redisConn.Get(fmt.Sprintf("googleauthstate:%s", state)).Bytes()
	if err != nil {
		return "", 0, err
	}

	var stateJson GoogleAuthState
	err = json.Unmarshal(stateJsonBytes, &stateJson)
	if err != nil {
		redisConn.Del(fmt.Sprintf("googleauthstate:%s", state)).Result()
		return "", 0, err
	}

	if stateJson.Version != 1 {
		redisConn.Del(fmt.Sprintf("googleauthstate:%s", state)).Result()
		err = fmt.Errorf("Unsupported state version %d for state %s", stateJson.Version, state)
		return "", 0, err
	}

	tok, err := oAuthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return "", 0, err
	}

	client := oAuthConfig.Client(oauth2.NoContext, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return "", 0, err
	}

	var respBodyBytes []byte
	if resp.Body != nil {
		defer resp.Body.Close()
		respBodyBytes, _ = ioutil.ReadAll(resp.Body)
	} else {
		err := fmt.Errorf("Invalid response from Google: %d (NO BODY)", resp.StatusCode)
		return "", 0, err
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("Invalid response from Google: %d %s", resp.StatusCode, string(respBodyBytes))
		return "", 0, err
	}

	return string(respBodyBytes), time.Duration(stateJson.Duration) * time.Second, err
}
