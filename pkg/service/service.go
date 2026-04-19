package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/containifyci/oauth2-storage/pkg/auth"
	"github.com/containifyci/oauth2-storage/pkg/config"
	"github.com/containifyci/oauth2-storage/pkg/proto"
	"github.com/containifyci/oauth2-storage/pkg/storage"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
)

type (
	Config = config.Config

	// TokenService represents a service for managing OAuth2 tokens.
	TokenService struct {
		cfg     Config
		mu      sync.RWMutex
		tokens  map[string]*proto.Installation
		storage storage.Storage
		proto.UnimplementedTokenServer
	}
)

// NewTokenService creates a new instance of TokenService.
func NewTokenService(cfg Config) *TokenService {
	tkSrv := TokenService{
		cfg:    cfg,
		tokens: make(map[string]*proto.Installation),
	}

	if cfg.StorageFile != "" {
		tkSrv.storage = storage.NewFileStorage(cfg.StorageFile)
	}
	err := tkSrv.Load()
	if err != nil {
		slog.Error("error loading tokens", "error", err)
	}
	return &tkSrv
}

func (s *TokenService) Save() error {
	if s.storage == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.storage.Save(s.tokens)
}

func (s *TokenService) Load() error {
	if s.storage == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.storage.Load()
	if err != nil {
		return err
	}
	s.tokens = data
	return nil
}

// RetrieveToken retrieves an OAuth2 token for a given GitHub user login name.
func (s *TokenService) RetrieveInstallation(ctx context.Context, req *proto.Installation) (*proto.Installation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, found := s.tokens[req.InstallationId]
	if !found {
		return nil, fmt.Errorf("requested token for %s not found", req.InstallationId)
	}

	return token, nil
}

// RetrieveToken retrieves an OAuth2 token for a given GitHub user login name.
func (s *TokenService) RetrieveToken(ctx context.Context, req *proto.SingleToken) (*proto.SingleToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tokens := s.tokens[req.InstallationId]
	if tokens == nil {
		slog.Error("requested token not found", "installationId", req.InstallationId)
		return nil, fmt.Errorf("requested token for %s not found", req.InstallationId)
	}
	for i, token := range tokens.Tokens {
		if token.User == req.Token.User {
			slog.Debug("found token", "installationId", req.InstallationId, "user", token.User)
			return &proto.SingleToken{
				InstallationId: req.InstallationId,
				Token:          tokens.Tokens[i],
			}, nil
		}
	}
	slog.Error("requested token not found", "installationId", req.InstallationId, "user", req.Token.User)
	return nil, fmt.Errorf("requested token for %s and user %s not found", req.InstallationId, req.Token.User)
}

// StoreToken stores an OAuth2 token for a given GitHub user login name.
func (s *TokenService) UpdateToken(ctx context.Context, req *proto.SingleToken) (*proto.SingleToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokens := s.tokens[req.InstallationId]
	if tokens == nil {
		return nil, fmt.Errorf("requested tokens for %s not found", req.InstallationId)
	}
	for i, token := range tokens.Tokens {
		if token.User == req.Token.User {
			tokens.Tokens[i] = req.Token
			return req, nil
		}
	}
	return req, nil
}

func (s *TokenService) StoreToken(ctx context.Context, req *proto.SingleToken) (*proto.SingleToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokens := s.tokens[req.InstallationId]
	if tokens == nil {
		s.tokens[req.InstallationId] = &proto.Installation{
			InstallationId: req.InstallationId,
			Tokens:         []*proto.CustomToken{req.Token},
		}
		tokens = s.tokens[req.InstallationId]
	}
	if tokens == nil {
		return nil, fmt.Errorf("requested token for %s not found", req.InstallationId)
	}
	for i, token := range tokens.Tokens {
		if token.User == req.Token.User {
			tokens.Tokens[i] = req.Token
			return req, nil
		}
	}
	tokens.Tokens = append(tokens.Tokens, req.Token)
	return req, nil
}

// RevokeToken(context.Context, *SingleToken) (*RevokeMessage, error)
func (s *TokenService) RevokeToken(ctx context.Context, req *proto.SingleToken) (*proto.RevokeMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokens := s.tokens[req.InstallationId]
	if tokens == nil {
		err := fmt.Errorf("requested token for installation %s not found", req.InstallationId)
		return &proto.RevokeMessage{Revoked: false, Error: &proto.RevokeMessage_Error{
			Message: err.Error(),
		}}, err
	}
	temp := tokens.Tokens[:0]
	revoked := false
	for _, token := range tokens.Tokens {
		if token.User != req.Token.User {
			temp = append(temp, token)
		} else {
			revoked = true
		}
	}
	s.tokens[req.InstallationId].Tokens = temp

	if revoked {
		return &proto.RevokeMessage{Revoked: revoked}, nil
	}

	err := fmt.Errorf("user %s has no token", req.Token.User)
	return &proto.RevokeMessage{Revoked: revoked, Error: &proto.RevokeMessage_Error{Message: err.Error()}}, err
}

// UpdateToken updates an existing OAuth2 token for a given GitHub user login name.
func (s *TokenService) StoreInstallation(ctx context.Context, req *proto.Installation) (*proto.Installation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Add installation
	s.tokens[req.InstallationId] = req
	return req, nil
}

// HTTP Server
func startHTTPServer(tokenService *TokenService) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/tokens/{installationId}", func(w http.ResponseWriter, r *http.Request) {
		installationId := r.PathValue("installationId")
		user := r.URL.Query().Get("user")
		slog.Debug("http request", "installationId", installationId)

		switch r.Method {
		case http.MethodGet:
			if user == "" {
				req := &proto.Installation{InstallationId: installationId}
				token, err := tokenService.RetrieveInstallation(context.Background(), req)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				respondJSON(w, token)
			} else {
				req := &proto.SingleToken{InstallationId: installationId, Token: &proto.CustomToken{User: user}}
				token, err := tokenService.RetrieveToken(context.Background(), req)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				respondJSON(w, token)
			}

		case http.MethodPost:
			if user == "" {
				var tokenRequest proto.Installation
				if err := decodeJSON(r.Body, &tokenRequest); err != nil {
					http.Error(w, "Invalid request body", http.StatusBadRequest)
					return
				}

				token, err := tokenService.StoreInstallation(context.Background(), &tokenRequest)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				respondJSON(w, token)
			} else {
				var tokenRequest proto.SingleToken
				if err := decodeJSON(r.Body, &tokenRequest); err != nil {
					http.Error(w, "Invalid request body", http.StatusBadRequest)
					return
				}

				token, err := tokenService.StoreToken(context.Background(), &tokenRequest)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				respondJSON(w, token)
			}

		case http.MethodPut:
			if user == "" {
				var tokenRequest proto.Installation
				if err := decodeJSON(r.Body, &tokenRequest); err != nil {
					http.Error(w, "Invalid request body", http.StatusBadRequest)
					return
				}

				token, err := tokenService.StoreInstallation(context.Background(), &tokenRequest)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				respondJSON(w, token)
			} else {
				var tokenRequest proto.SingleToken
				if err := decodeJSON(r.Body, &tokenRequest); err != nil {
					http.Error(w, "Invalid request body", http.StatusBadRequest)
					return
				}

				token, err := tokenService.UpdateToken(context.Background(), &tokenRequest)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				respondJSON(w, token)
			}
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", tokenService.cfg.HTTPPort),
		Handler: mux,
	}
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server exited", "error", err)
			os.Exit(1)
		}
	}()
	return srv
}

// gRPC Server
type AuthInterceptor struct {
	authSrv *auth.AuthService
}

func NewAuthInterceptor(publicKey string) *AuthInterceptor {
	var authSrv *auth.AuthService
	if publicKey != "" {
		authSrv = auth.NewVerifyService(publicKey)
	}

	return &AuthInterceptor{authSrv: authSrv}
}

func (interceptor *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		slog.Debug("unary interceptor", "method", info.FullMethod)

		err := interceptor.authorize(ctx, "dunebot")
		if err != nil {
			slog.Error("unauthorized request", "error", err)
			return nil, err
		}

		return handler(ctx, req)
	}
}

func (interceptor *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		slog.Debug("stream interceptor", "method", info.FullMethod)

		err := interceptor.authorize(stream.Context(), "dunebot")
		if err != nil {
			slog.Error("unauthorized request", "error", err)
			return err
		}

		return handler(srv, stream)
	}
}

func (interceptor *AuthInterceptor) authorize(ctx context.Context, serviceName string) error {

	if interceptor.authSrv == nil {
		slog.Info("Authentication is disabled (no public key)")
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("metadata is not provided")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return fmt.Errorf("authorization token is not provided")
	}

	accessToken := values[0]
	claims, err := interceptor.authSrv.ValidateToken(accessToken)
	if err != nil {
		return fmt.Errorf("access token is invalid: %v", err)
	}

	slog.Debug("received claim", "claims", claims)
	val := jwt.NewValidator(jwt.WithSubject(fmt.Sprintf("service:%s", serviceName)))

	err = val.Validate(claims)

	if err != nil {
		return fmt.Errorf("access token claims are invalid: %v", err)
	}

	return nil
}

func StartGRPCServer(tokenService *TokenService) *grpc.Server {

	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", tokenService.cfg.GRPCPort))
	if err != nil {
		slog.Error("Failed to listen", "error", err)
		os.Exit(1)
	}

	slog.Debug("starting gRPC server", "publicKey", tokenService.cfg.PublicKey)

	interceptor := NewAuthInterceptor(tokenService.cfg.PublicKey)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.Unary()),
		grpc.StreamInterceptor(interceptor.Stream()),
	)

	proto.RegisterTokenServer(server, tokenService)

	// Register reflection service on gRPC server.
	reflection.Register(server)

	go func() {
		slog.Debug("gRPC server listening", "port", tokenService.cfg.GRPCPort)

		if err := server.Serve(listen); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			slog.Error("Failed to serve", "error", err)
			os.Exit(1)
		}
	}()
	return server
}

func StartServers(cfg Config) error {
	tokenService := NewTokenService(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ctx := context.Background()

	errCh := make(chan error, 1)

	// Log errors from the SyncWithError goroutine
	go func() {
		for err := range errCh {
			slog.Error("Failed sync token storage", "error", err)
		}
	}()

	tokenService.SyncWithError(ctx, cfg.TokenSyncPeriodDuration(), errCh)

	// Run HTTP and gRPC servers concurrently
	srv := startHTTPServer(tokenService)
	grpcSrv := StartGRPCServer(tokenService)

	slog.Debug("Server started, waiting for termination")

	<-sigCh
	ctxShutDown, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxShutDown); err != nil {
		slog.Error("server shutdown failed", "error", err)
		os.Exit(1)
	}

	slog.Debug("server exited properly")

	grpcSrv.GracefulStop()
	err := tokenService.Save()
	if err != nil {
		slog.Error("error saving tokens", "error", err)
	}
	return nil
}

func (s *TokenService) SyncWithError(ctx context.Context, period time.Duration, errCh chan<- error) {
	if period == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(period)
		for {
			select {
			case <-ticker.C:
				err := s.Save()
				if err != nil {
					slog.Error("error saving tokens", "error", err)
					if errCh != nil {
						select {
						case errCh <- err:
						default:
							slog.Error("error channel is blocked", "error", err)
						}
					}
				}
			case <-ctx.Done():
				close(errCh)
				return
			}
		}
	}()
}

// Utility functions

// respondJSON sends a JSON response.
func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := encodeJSON(w, data); err != nil {
		http.Error(w, "Failed to encode JSON response", http.StatusInternalServerError)
	}
}

// encodeJSON encodes data to JSON and writes it to the response writer.
func encodeJSON(w http.ResponseWriter, data interface{}) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(data)
}

// decodeJSON decodes JSON from the request body into the provided interface.
func decodeJSON(body io.Reader, v interface{}) error {
	decoder := json.NewDecoder(body)
	return decoder.Decode(v)
}
