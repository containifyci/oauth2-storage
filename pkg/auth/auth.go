package auth

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ServiceClaims struct {
	ServiceName string
}

func (s *ServiceClaims) Service() string {
	return fmt.Sprintf("service:%s", s.ServiceName)
}

type AuthService struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewSigningService(privateKey string) *AuthService {
	var ecPrivateKey *ecdsa.PrivateKey
	if privateKey != "" {
		data, err := base64.StdEncoding.DecodeString(privateKey)
		if err != nil {
			slog.Error("error decoding private key", "error", err)
			os.Exit(1)
		}

		block, _ := pem.Decode(data)
		if block == nil {
			slog.Error("Error decoding PEM block")
			os.Exit(1)
		}

		ecPrivateKey, err = x509.ParseECPrivateKey(block.Bytes)

		if err != nil {
			slog.Error("Error retrieving private key", "error", err)
			os.Exit(1)
		}
	}

	return &AuthService{privateKey: ecPrivateKey}
}

func (a *AuthService) IsEnabled() bool {
	return a.privateKey != nil || a.publicKey != nil
}

func NewVerifyService(publicKey string) *AuthService {
	if publicKey == "" {
		return &AuthService{}
	}
	data, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		slog.Error("error decoding public key", "error", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		slog.Error("failed to parse PEM block containing the public key")
		os.Exit(1)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.Error("failed to parse DER encoded public key", "error", err)
		os.Exit(1)
	}

	if key, ok := pub.(*ecdsa.PublicKey); ok {
		return &AuthService{publicKey: key}
	}
	slog.Error("Failed to get ecdsa Public Key", "type", reflect.TypeOf(pub))
	os.Exit(1)
	return nil
}

func (a *AuthService) CreateTokenFnc(scl ServiceClaims) func() string {
	return func() string {
		if a.privateKey == nil {
			cl := jwt.RegisteredClaims{
				Issuer:    scl.Service(),
				Subject:   scl.Service(),
				Audience:  []string{scl.Service()},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(time.Minute * -5)),
			}
			// Create the unsigned token
			token := jwt.NewWithClaims(jwt.SigningMethodNone, cl)

			// Generate the JWT string (without signing)
			tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
			if err != nil {
				slog.Error("Error creating unsigned token", "error", err)
				os.Exit(1)
			}
			return tokenString
		}
		cl := jwt.RegisteredClaims{
			Issuer:    scl.Service(),
			Subject:   scl.Service(),
			Audience:  []string{scl.Service()},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(time.Minute * -5)),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES512, cl)

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(a.privateKey)
		if err != nil {
			slog.Error("Error signing token", "error", err)
			os.Exit(1)
		}
		return tokenString
	}
}

func (a *AuthService) CreateToken(scl ServiceClaims) string {
	return a.CreateTokenFnc(scl)()
}

func (a *AuthService) ValidateToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			switch token.Method {
			case jwt.SigningMethodES512:
				return a.publicKey, nil
			case jwt.SigningMethodNone:
				return jwt.UnsafeAllowNoneSignatureType, nil
			default:
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		},
	)

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
