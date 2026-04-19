package storage

import (
	"context"
	"os"
	"testing"

	"github.com/containifyci/oauth2-storage/pkg/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type TestContext struct {
	fileStorage FileStorage
}

type cxtTestKey struct{}

var ctx context.Context

/*
Setup the storages with dummy data for testing
*/
func setup() {
	fileStorage := FileStorage{
		File: os.TempDir() + "/dunebot-token-storage.json",
	}

	ctx = context.WithValue(context.Background(), cxtTestKey{}, TestContext{fileStorage: fileStorage})
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

	err := fileStorage.Save(installations)
	if err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	os.Exit(code)
}

//TODO add error handling test cases

func TestFileStorage_Save(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "prefix")
	assert.NoError(t, err)

	storage := FileStorage{
		File: file.Name(),
	}
	installations := map[string]*proto.Installation{
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
	err = storage.Save(installations)
	assert.NoError(t, err)
}

func TestFileStorage_Load(t *testing.T) {
	ctx := ctx.Value(cxtTestKey{}).(TestContext)
	data, err := ctx.fileStorage.Load()

	assert.NoError(t, err)
	assert.Equal(t, 1, len(data))
	assert.Equal(t, "1", data["1"].InstallationId)
}
