package storage

import (
	"encoding/json"
	"os"

	"github.com/containifyci/github-oauth2-service/pkg/proto"
)

const (
	DefaultK8sSecret = "dunebot-token-storage"
)

type FileStorage struct {
	File string
}

type Storage interface {
	Load() (map[int64]*proto.Installation, error)
	Save(tokens map[int64]*proto.Installation) error
}

func NewFileStorage(file string) *FileStorage {
	return &FileStorage{
		File: file,
	}
}

func (s *FileStorage) Load() (map[int64]*proto.Installation, error) {
	data, err := os.ReadFile(s.File)
	if err != nil {
		return nil, err
	}

	var tokens map[int64]*proto.Installation
	err = json.Unmarshal(data, &tokens)
	return tokens, err
}

func (s *FileStorage) Save(tokens map[int64]*proto.Installation) error {
	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}

	return os.WriteFile(s.File, data, 0644)
}

