package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/containifyci/oauth2-storage/pkg/auth"
	"github.com/containifyci/oauth2-storage/pkg/config"
	"github.com/containifyci/oauth2-storage/pkg/proto"
	"github.com/containifyci/oauth2-storage/pkg/service"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

type DeRef struct {
	Validate *bool
}

func TestDeRef(t *testing.T) {
	t.Parallel()

	deRef := DeRef{}
	assert.Nil(t, deRef.Validate)

	deRef.Validate = new(bool)
	*deRef.Validate = true
}

func TestRetrieveToken(t *testing.T) {
	t.Parallel()

	config := setupGRPCClient(t, "user")

	token, err := config.RetrieveToken()
	assert.NoError(t, err)

	assert.NotNil(t, token)
	assert.Equal(t, "access", token.AccessToken)
	assert.Equal(t, "refresh", token.RefreshToken)
	assert.Equal(t, "type", token.TokenType)
}

func TestStoreToken(t *testing.T) {
	t.Parallel()

	config := setupGRPCClient(t, "user2")

	token := &oauth2.Token{
		AccessToken:  "new_access",
		TokenType:    "new_type",
		RefreshToken: "new_refresh",
		Expiry:       time.Now(),
	}

	err := config.StoreToken(token)
	assert.NoError(t, err)

	token2, err := config.RetrieveToken()
	assert.NoError(t, err)

	assert.NotNil(t, token)
	assert.Equal(t, token.AccessToken, token2.AccessToken)
	assert.Equal(t, token.RefreshToken, token2.RefreshToken)
	assert.Equal(t, token.TokenType, token2.TokenType)
}

func TestRevokeToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		user           string
		installationId string
		err            error
	}{
		{name: "revoke token", user: "user", installationId: "1"},
		{name: "revoke token no token found", user: "user1", installationId: "1", err: fmt.Errorf("user user1 has no token")},
		{name: "revoke token no installation found", user: "user", installationId: "2", err: fmt.Errorf("requested token for installation 2 not found")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := setupGRPCClient(t, tt.user)
			config.InstallationId = tt.installationId
			err := config.RevokeToken()
			if tt.err != nil {
				assert.ErrorContains(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTokenSourceFrom(t *testing.T) {
	config := setupGRPCClient(t, "user")

	srv := NewMockOAuth2Server()
	defer srv.Close()
	config.OAuth2Config.Endpoint = srv.Endpoint()

	ctx := context.Background()
	tokenSource := config.TokenSourceFrom(ctx)

	token, err := tokenSource.Token()
	assert.NoError(t, err)

	assert.NotNil(t, token)
	assert.Equal(t, "mocktoken", token.AccessToken)
	assert.Equal(t, "mockrefresh", token.RefreshToken)
	assert.Equal(t, "mocktype", token.TokenType)
}

// utility functions

func setupGRPCClient(t *testing.T, user string) Config {
	privateKey, publicKey := generateECDSAKey()
	cfg := setupTokenService(t, tokens)

	go func() {
		cfg.PublicKey = publicKey
		err := service.StartServers(cfg)
		assert.NoError(t, err)
	}()
	// wait for the server to start
	// time.Sleep(5 * time.Second)

	signer := auth.NewSigningService(privateKey)

	tokenFnc := signer.CreateTokenFnc(auth.ServiceClaims{ServiceName: "dunebot"})

	cfg2 := config.GithubOAuthConfig{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		Scopes:       []string{"repo", "user"},
		RedirectURL:  "http://localhost:8080/oauth2/callback",
	}

	config := Config{
		AuthInterceptor: *NewAuthInterceptor(tokenFnc),
		Addr:            fmt.Sprintf(":%d", cfg.GRPCPort),
		Ctx:             context.Background(),
		InstallationId:  "1",
		User:            user,
		OAuth2Config:    cfg2.GetConfig(),
	}
	config.OAuth2Config.Endpoint.AuthURL = fmt.Sprintf("http://localhost:%d", cfg.GRPCPort)
	return config
}

func setupTokenService(t *testing.T, tokens string) service.Config {
	s := proto.Installation{
		InstallationId: "1",
		Tokens: []*proto.CustomToken{
			{
				AccessToken:  "access",
				RefreshToken: "refresh",
				TokenType:    "type",
				User:         "user",
				Expiry:       timestamppb.New(time.Now()),
			},
		},
	}

	m := make(map[int64]*proto.Installation)
	m[1] = &s
	b, err := json.Marshal(m)
	assert.NoError(t, err)

	file := t.TempDir() + "/tokens.json"

	err = os.WriteFile(file, b, 0644)
	assert.NoError(t, err)

	cfg := service.Config{
		TokenSyncPeriod: "1m",
		StorageFile:     file,
		GRPCPort:        getFreePort(),
	}

	return cfg
}

func generateECDSAKey() (privateKey string, publicKey string) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Extract public component.
	pub := key.Public()

	privKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "ECDSA PRIVATE KEY",
			Bytes: privKey,
		},
	)

	privateKey = base64.StdEncoding.EncodeToString(keyPEM)

	pubKey, err := x509.MarshalPKIXPublicKey(pub.(*ecdsa.PublicKey))
	if err != nil {
		panic(err)
	}

	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "ECDSA PUBLIC KEY",
			Bytes: pubKey,
		},
	)
	publicKey = base64.StdEncoding.EncodeToString(pubPEM)
	return privateKey, publicKey
}

func getFreePort() int {
	var a *net.TCPAddr
	a, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	var l *net.TCPListener
	l, err = net.ListenTCP("tcp", a)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

const tokens = `{"1":{"installation_id":1,"tokens":[{"access_token":"access","refresh_token":"refresh","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"type","user":"user"}]}}`
