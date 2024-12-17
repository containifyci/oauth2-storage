package storage

import (
	"context"
	"os"
	"testing"

	"github.com/containifyci/github-oauth2-service/pkg/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	testclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)


type TestContext struct {
	k8sStorage  K8sStorage
	fileStorage FileStorage
}

type cxtTestKey struct{}
var ctx context.Context

/*
Setup the storages with dummy data for testing
*/
func setup() {
	k8sStorage := K8sStorage{
		Namespace: "test",
		Clientset: testclient.NewSimpleClientset(),
	}
	fileStorage := FileStorage{
		File: os.TempDir() + "/dunebot-token-storage.json",
	}

	ctx = context.WithValue(context.Background(), cxtTestKey{}, TestContext{k8sStorage: k8sStorage, fileStorage: fileStorage})
	installations := map[int64]*proto.Installation{
		1: {
			InstallationId: 1,
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

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	os.Exit(code)
}

func TestNewK8sStorage(t *testing.T) {
	storage, err := NewK8sStorage("test", func() (*rest.Config, error) {
		return &rest.Config{}, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, "test", storage.Namespace)
}

//TODO add error handling test cases

func TestK8sStorage_Load(t *testing.T) {
	ctx := ctx.Value(cxtTestKey{}).(TestContext)
	data, err := ctx.k8sStorage.Load()

	assert.NoError(t, err)
	assert.Equal(t, 1, len(data))
	assert.Equal(t, int64(1), data[1].InstallationId)
}

func TestK8sStorage_Save(t *testing.T) {
	clientset := testclient.NewSimpleClientset()
	storage := K8sStorage{
		Namespace: "test",
		Clientset: clientset,
	}
	installations := map[int64]*proto.Installation{
		2: {
			InstallationId: 2,
			Tokens: []*proto.CustomToken{{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				Expiry:       timestamppb.Now(),
				TokenType:    "token-type",
				User:         "user",
			},
			},
		}}
	//First time save will create the k8s secret
	err := storage.Save(installations)
	assert.NoError(t, err)
	//Second time save will update the k8s secret
	err = storage.Save(installations)
	assert.NoError(t, err)
}

func TestFileStorage_Save(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "prefix")
	assert.NoError(t, err)

	storage := FileStorage{
		File: file.Name(),
	}
	installations := map[int64]*proto.Installation{
		2: {
			InstallationId: 2,
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
	assert.Equal(t, int64(1), data[1].InstallationId)
}
