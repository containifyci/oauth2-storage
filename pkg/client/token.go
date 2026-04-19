package client

import (
	"context"
	"errors"
	"log/slog"

	"github.com/containifyci/oauth2-storage/pkg/proto"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type OAuth2Config = oauth2.Config
type Endpoint = oauth2.Endpoint

type Config struct {
	Ctx            context.Context
	InstallationId string
	User           string
	Addr           string
	*OAuth2Config
	AuthInterceptor
}

/*
GRPC Authentication Interceptor

Inspired by the following tutorial https://dev.to/techschoolguru/use-grpc-interceptor-for-authorization-with-jwt-1c5h
*/
type AuthInterceptor struct {
	accessTokenFnc func() string
}

func (interceptor *AuthInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		slog.Debug("unary interceptor", "method", method)

		return invoker(interceptor.attachToken(ctx), method, req, reply, cc, opts...)
	}
}

func (interceptor *AuthInterceptor) Stream() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		slog.Debug("stream interceptor", "method", method)

		return streamer(interceptor.attachToken(ctx), desc, cc, method, opts...)
	}
}

func (interceptor *AuthInterceptor) attachToken(ctx context.Context) context.Context {
	accessToken := interceptor.accessTokenFnc()
	if accessToken != "" {
		return metadata.AppendToOutgoingContext(ctx, "authorization", accessToken)
	}
	return ctx
}

func NewAuthInterceptor(accessTokenFnc func() string) *AuthInterceptor {
	return &AuthInterceptor{accessTokenFnc: accessTokenFnc}
}

// END GRPC Authentication Interceptor

func NewClient(auth AuthInterceptor, addr string) (proto.TokenClient, func() error, error) {
	// Initialize a gRPC connection
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(auth.Unary()),
		grpc.WithStreamInterceptor(auth.Stream()))
	if err != nil {
		slog.Error("Failed to connect to gRPC server", "error", err)
		return nil, func() error { return nil }, err
	}

	// Initialize a gRPC client
	return proto.NewTokenClient(conn), func() error { return conn.Close() }, nil
}

func (c *Config) StoreToken(token *oauth2.Token) error {
	grpcClient, close, err := NewClient(c.AuthInterceptor, c.Addr)
	defer func() {
		if err := close(); err != nil {
			slog.Error("Failed to close gRPC connection", "error", err)
		}
	}()
	if err != nil {
		slog.Error("Failed to connect to gRPC server", "error", err)
		return err
	}
	tk := &proto.CustomToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       timestamppb.New(token.Expiry.UTC()),
		User:         c.User,
	}

	slog.Debug("Store Token", "user", tk.User)
	slog.Debug("Token Expiry", "expiry", tk.Expiry.AsTime())

	_, err = grpcClient.StoreToken(c.Ctx, &proto.SingleToken{
		InstallationId: c.InstallationId,
		Token:          tk,
	})
	if err != nil {
		slog.Error("Failed to store token", "error", err)
		return err
	}
	return nil
}

func (c *Config) RetrieveToken() (*oauth2.Token, error) {
	grpcClient, close, err := NewClient(c.AuthInterceptor, c.Addr)

	defer func() {
		if err := close(); err != nil {
			slog.Error("Failed to close gRPC connection", "error", err)
		}
	}()
	if err != nil {
		slog.Error("Failed to connect to gRPC server", "error", err)
		return nil, err
	}

	tk, err := grpcClient.RetrieveToken(c.Ctx, &proto.SingleToken{
		InstallationId: c.InstallationId,
		Token: &proto.CustomToken{
			User: c.User,
		},
	})
	if err != nil {
		slog.Error("Failed to retrieve token from gRPC server", "error", err)
		return nil, err
	}

	return &oauth2.Token{
		AccessToken:  tk.Token.AccessToken,
		RefreshToken: tk.Token.RefreshToken,
		TokenType:    tk.Token.TokenType,
		Expiry:       tk.Token.Expiry.AsTime(),
	}, nil
}

func (c *Config) RevokeToken() error {
	grpcClient, close, err := NewClient(c.AuthInterceptor, c.Addr)
	defer func() {
		if err := close(); err != nil {
			slog.Error("Failed to close gRPC connection", "error", err)
		}
	}()
	if err != nil {
		slog.Error("Failed to connect to gRPC server", "error", err)
		return err
	}

	message, err := grpcClient.RevokeToken(c.Ctx, &proto.SingleToken{
		InstallationId: c.InstallationId,
		Token: &proto.CustomToken{
			User: c.User,
		},
	})
	if err != nil {
		slog.Error("Failed to revoke token from gRPC server", "error", err)
		return err
	}

	if message.Revoked {
		slog.Debug("Successfully revoked token", "user", c.User)
		return nil
	}

	return errors.New(message.Error.Message)
}

func (c *Config) TokenSourceFrom(ctx context.Context) oauth2.TokenSource {
	t, err := c.RetrieveToken()
	if err != nil {
		slog.Error("Failed to retrieve token from gRPC server", "error", err)
		return nil
	}
	slog.Debug("Retrieved token", "token", t)
	return c.TokenSource(ctx, t)
}

func (c *Config) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	rts := &DuneBotTokenSource{
		t:      t,
		source: c.OAuth2Config.TokenSource(ctx, t),
		config: c,
	}
	return oauth2.ReuseTokenSource(t, rts)
}

type DuneBotTokenSource struct {
	t      *oauth2.Token
	source oauth2.TokenSource
	config *Config
}

func (t *DuneBotTokenSource) Token() (*oauth2.Token, error) {
	token, err := t.source.Token()
	if err != nil {
		return nil, err
	}
	if token.RefreshToken != t.t.RefreshToken {
		if err := t.config.StoreToken(token); err != nil {
			return nil, err
		}
	}
	return token, nil
}
