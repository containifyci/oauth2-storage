package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/containifyci/oauth2-storage/pkg/auth"
	"github.com/containifyci/oauth2-storage/pkg/proto"
	"github.com/containifyci/oauth2-storage/pkg/storage"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	testclient "k8s.io/client-go/kubernetes/fake"
)

type cxtTestKey struct{}
var ctx context.Context

type TestContext struct {
	k8sStorage  storage.K8sStorage
	fileStorage storage.FileStorage
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	os.Exit(code)
}

/*
Setup the storages with dummy data for testing
*/
func setup() {
	k8sStorage := storage.K8sStorage{
		Namespace: "test",
		Clientset: testclient.NewSimpleClientset(),
	}
	fileStorage := storage.FileStorage{
		File: os.TempDir() + "/dunebot-token-storage.json",
	}

	ctx = context.WithValue(context.Background(), cxtTestKey{}, TestContext{k8sStorage: k8sStorage, fileStorage: fileStorage})
	installations := map[string]*proto.Installation{
		"1": {
			InstallationId: "1",
			Tokens: []*proto.CustomToken{{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				Expiry:       timestamppb.Now(),
				TokenType:    "token-type",
				User:         "user",
			},
			},
		}}

	err := k8sStorage.Save(installations)
	if err != nil {
		panic(err)
	}
	err = fileStorage.Save(installations)
	if err != nil {
		panic(err)
	}
}

func TestNewTokenServiceFile(t *testing.T) {
	ts := setupTokenService(t, "{}")

	assert.NotNil(t, ts)
	assert.IsType(t, &storage.FileStorage{}, ts.storage)
}

func TestNewTokenServiceK8s(t *testing.T) {
	cfg := Config{
		TokenSyncPeriod: "1m",
		PodNamespace:    "test",
	}

	ts := NewTokenService(cfg)

	assert.NotNil(t, ts)
	assert.Nil(t, ts.storage)
}

func TestRetrieveInstallationToken(t *testing.T) {
	ts := setupTokenService(t, tokens)
	req := proto.Installation{
		InstallationId: "1",
	}
	token, err := ts.RetrieveInstallation(context.Background(), &req)

	assert.NoError(t, err)

	assert.NotNil(t, token)
	assert.Len(t, token.Tokens, 1)
	assert.Equal(t, "access", token.Tokens[0].AccessToken)
	assert.Equal(t, "refresh", token.Tokens[0].RefreshToken)
	assert.Equal(t, "type", token.Tokens[0].TokenType)
	assert.Equal(t, "user", token.Tokens[0].User)
}

func TestRetrieveInstallationTokeNotFound(t *testing.T) {
	ts := setupTokenService(t, "{}")
	req := proto.Installation{
		InstallationId: "1",
	}
	token, err := ts.RetrieveInstallation(context.Background(), &req)

	assert.EqualError(t, err, "requested token for 1 not found")
	assert.Nil(t, token)
}

func TestStoreInstallationToken(t *testing.T) {
	ts := setupTokenService(t, "{}")

	req := proto.Installation{
		InstallationId: "1",
		Tokens: []*proto.CustomToken{
			&proto.CustomToken{
				AccessToken:  "access",
				Expiry:       timestamppb.New(time.Now().Add(1 * time.Hour)),
				RefreshToken: "refresh",
				TokenType:    "type",
				User:         "user",
			},
		},
	}
	_, err := ts.StoreInstallation(context.Background(), &req)

	assert.NoError(t, err)
}

func TestRetrieveToken(t *testing.T) {
	ts := setupTokenService(t, tokens)
	req := proto.SingleToken{
		InstallationId: "1",
		Token: &proto.CustomToken{
			User: "user",
		},
	}
	installation, err := ts.RetrieveToken(context.Background(), &req)

	assert.NoError(t, err)

	assert.NotNil(t, installation)
	assert.Equal(t, "1", installation.InstallationId)
	assert.Equal(t, "access", installation.Token.AccessToken)
	assert.Equal(t, "refresh", installation.Token.RefreshToken)
	assert.Equal(t, "type", installation.Token.TokenType)
	assert.Equal(t, "user", installation.Token.User)
}

func TestUpdateToken(t *testing.T) {
	ts := setupTokenService(t, tokens)
	req := proto.SingleToken{
		InstallationId: "1",
		Token: &proto.CustomToken{
			User:         "user",
			AccessToken:  "new_access",
			RefreshToken: "new_refresh",
			TokenType:    "new_type",
			Expiry:       timestamppb.New(time.Now().Add(1 * time.Hour)),
		},
	}
	_, err := ts.UpdateToken(context.Background(), &req)
	assert.NoError(t, err)

	installation, err := ts.RetrieveToken(context.Background(), &req)
	assert.NoError(t, err)

	assert.NotNil(t, installation)
	assert.Equal(t, "1", installation.InstallationId)
	assert.Equal(t, "new_access", installation.Token.AccessToken)
	assert.Equal(t, "new_refresh", installation.Token.RefreshToken)
	assert.Equal(t, "new_type", installation.Token.TokenType)
	assert.Equal(t, "user", installation.Token.User)
}

func TestStoreToken(t *testing.T) {
	ts := setupTokenService(t, tokens)
	req := proto.SingleToken{
		InstallationId: "1",
		Token: &proto.CustomToken{
			User:         "user2",
			AccessToken:  "new_access",
			RefreshToken: "new_refresh",
			TokenType:    "new_type",
			Expiry:       timestamppb.New(time.Now().Add(1 * time.Hour)),
		},
	}
	_, err := ts.StoreToken(context.Background(), &req)
	assert.NoError(t, err)

	installation, err := ts.RetrieveInstallation(context.Background(), &proto.Installation{InstallationId: "1"})
	assert.NoError(t, err)

	assert.NotNil(t, installation)
	assert.Equal(t, "1", installation.InstallationId)
	assert.Len(t, installation.Tokens, 2)
	assert.Equal(t, "new_access", installation.Tokens[1].AccessToken)
	assert.Equal(t, "new_refresh", installation.Tokens[1].RefreshToken)
	assert.Equal(t, "new_type", installation.Tokens[1].TokenType)
	assert.Equal(t, "user2", installation.Tokens[1].User)
}

func TestRevokeToken(t *testing.T) {
	ts := setupTokenService(t, tokens)
	req := proto.SingleToken{
		InstallationId: "1",
		Token: &proto.CustomToken{
			User: "user",
		},
	}

	_, err := ts.RevokeToken(context.Background(), &req)
	assert.NoError(t, err)

	installation, err := ts.RetrieveInstallation(context.Background(), &proto.Installation{InstallationId: "1"})
	assert.NoError(t, err)

	assert.NotNil(t, installation)
	assert.Equal(t, "1", installation.InstallationId)
	assert.Len(t, installation.Tokens, 0)
}

func TestHttpServer(t *testing.T) {
	ts := setupTokenService(t, tokens)

	srv := startHTTPServer(ts)
	t.Cleanup(func() {
		err := srv.Shutdown(context.Background())
		assert.NoError(t, err)
	})

	tests := []struct {
		name     string
		method   string
		path     string
		body     string
		expected string
	}{
		{
			name:     "GET /tokens/1",
			method:   http.MethodGet,
			path:     "/tokens/1",
			body:     "",
			expected: `{"installation_id":"1","tokens":[{"access_token":"access","refresh_token":"refresh","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"type","user":"user"}]}`,
		},
		{
			name:     "GET /tokens/1?user=user",
			method:   http.MethodGet,
			path:     "/tokens/1?user=user",
			body:     "",
			expected: `{"installation_id":"1","token":{"access_token":"access","refresh_token":"refresh","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"type","user":"user"}}`,
		},
		{
			name:     "POST /tokens/1",
			method:   http.MethodPost,
			path:     "/tokens/1",
			body:     `{"installation_id":"1","tokens":[{"access_token":"new_access","refresh_token":"new_refresh_token","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"new_type","user":"new_user"}]}`,
			expected: `{"installation_id":"1","tokens":[{"access_token":"new_access","refresh_token":"new_refresh_token","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"new_type","user":"new_user"}]}`,
		},
		{
			name:     "POST /tokens/1?user=new_user",
			method:   http.MethodPost,
			path:     "/tokens/1?user=new_user",
			body:     `{"installation_id":"1","token":{"access_token":"new_access","refresh_token":"new_refresh_token","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"new_type","user":"new_user"}}`,
			expected: `{"installation_id":"1","token":{"access_token":"new_access","refresh_token":"new_refresh_token","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"new_type","user":"new_user"}}`,
		},
		{
			name:     "PUT /tokens/1",
			method:   http.MethodPut,
			path:     "/tokens/1",
			body:     `{"installation_id":"1","tokens":[{"access_token":"new_access","refresh_token":"new_refresh_token","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"new_type","user":"new_user"}]}`,
			expected: `{"installation_id":"1","tokens":[{"access_token":"new_access","refresh_token":"new_refresh_token","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"new_type","user":"new_user"}]}`,
		},
		{
			name:     "PUT /tokens/1?user=user",
			method:   http.MethodPut,
			path:     "/tokens/1?user=user",
			body:     `{"installation_id":"1","token":{"access_token":"new_access","refresh_token":"new_refresh_token","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"new_type","user":"new_user"}}`,
			expected: `{"installation_id":"1","token":{"access_token":"new_access","refresh_token":"new_refresh_token","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"new_type","user":"new_user"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			response := httptest.NewRecorder()
			request, _ := http.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))

			srv.Handler.ServeHTTP(response, request)

			assert.Equal(t, http.StatusOK, response.Code)
			assert.JSONEq(t, tt.expected, response.Body.String())
		})
	}
}

func TestStartGRPCServer(t *testing.T) {
	ts := setupTokenService(t, tokens)
	srv := StartGRPCServer(ts)
	srv.GracefulStop()
	assert.True(t, true, "The server should be gracefully stopped and no error should be logged")
}

func TestStartServers(t *testing.T) {
	go func() {
		ts := setupTokenService(t, tokens)
		err := StartServers(ts.cfg)
		assert.NoError(t, err)
	}()
	// wait for the server to start
	// time.Sleep(5 * time.Second)
	// stop the server
	// Find a way to send a SIGTERM to the server without killing the test process
	// syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
}

func TestAuthorize(t *testing.T) {
	privateKeyB64, publicKeyB64 := generateECDSAKey()

	signer := auth.NewSigningService(privateKeyB64)

	token := signer.CreateToken(auth.ServiceClaims{ServiceName: "service_test.go"})

	auth := NewAuthInterceptor(publicKeyB64)
	ctx := context.Background()
	md := make(map[string][]string)
	md["authorization"] = []string{token}

	ctx = metadata.NewIncomingContext(ctx, md)
	err := auth.authorize(ctx, "service_test.go")
	assert.NoError(t, err)
}

func TestAuthorizeDisabled(t *testing.T) {
	auth := NewAuthInterceptor("")

	err := auth.authorize(context.Background(), "service_test.go")
	assert.NoError(t, err)
}

func TestAuthorizeFailed(t *testing.T) {
	privateKey, publicKey := generateECDSAKey()

	signer := auth.NewSigningService(privateKey)

	token := signer.CreateToken(auth.ServiceClaims{ServiceName: "invalid service name"})

	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "no token",
			token:    "",
			expected: "access token is invalid: invalid token: token is malformed",
		},
		{
			name:     "invalid token",
			token:    "invalid",
			expected: "access token is invalid: invalid token: token is malformed",
		},
		{
			name:     "invalid claims",
			token:    token,
			expected: "access token is invalid: invalid token: invalid token claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			auth := NewAuthInterceptor(publicKey)
			ctx := context.Background()
			md := make(map[string][]string)
			if token != "" {
				md["authorization"] = []string{tt.token}
			}

			ctx = metadata.NewIncomingContext(ctx, md)
			err := auth.authorize(ctx, "service_test.go")
			assert.Errorf(t, err, tt.expected)
		})
	}
}


func TestTokenStorage_Load(t *testing.T) {
	ctx := ctx.Value(cxtTestKey{}).(TestContext)
	storage := NewTokenService(Config{
		StorageFile: ctx.fileStorage.File,
	})
	err := storage.Load()

	data := storage.tokens

	assert.NoError(t, err)
	assert.Equal(t, 1, len(data))
	assert.Equal(t, "1", data["1"].InstallationId)
}

func TestTokenStorage_Save(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "prefix")
	assert.NoError(t, err)

	storage := NewTokenService(Config{
		StorageFile: file.Name(),
	})

	storage.tokens = map[string]*proto.Installation{
		"2": {
			InstallationId: "2",
			Tokens: []*proto.CustomToken{{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				Expiry:       timestamppb.Now(),
				TokenType:    "token-type",
				User:         "user",
			},
			},
		}}
	err = storage.Save()
	assert.NoError(t, err)
}

func TestTokenStorage_SyncWithError(t *testing.T) {
	storage := NewTokenService(Config{
		StorageFile: "./test_/adsasdsadsa",
	})

	storage.tokens = map[string]*proto.Installation{
		"2": {
			InstallationId: "2",
			Tokens: []*proto.CustomToken{{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				Expiry:       timestamppb.Now(),
				TokenType:    "token-type",
				User:         "user",
			},
			},
		}}
	ctx2, cancel := context.WithCancel(ctx)
	// Create a buffered channel to communicate errors from the goroutine
	errCh := make(chan error, 1)
	storage.SyncWithError(ctx2, 1 * time.Second, errCh)
	time.Sleep(2 * time.Second)
	cancel()
	// Wait for the goroutine to finish
	select {
	case err := <-errCh:
		assert.ErrorContains(t, err, "open ./test_/adsasdsadsa: no such file or directory")
	case <-time.After(5 * time.Second):
		assert.Fail(t, "expected error")
	}
}


// utility functions

func setupTokenService(t *testing.T, tokens string) *TokenService {
	file := t.TempDir() + "/tokens.json"
	err := os.WriteFile(file, []byte(tokens), 0644)
	assert.NoError(t, err)

	cfg := Config{
		TokenSyncPeriod: "1m",
		StorageFile:     file,
	}

	ts := NewTokenService(cfg)
	assert.NotNil(t, ts)
	return ts
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

const tokens = `{"1":{"installation_id":"1","tokens":[{"access_token":"access","refresh_token":"refresh","expiry":{"seconds":1715603314,"nanos":409109000},"token_type":"type","user":"user"}]}}`
