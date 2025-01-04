package storage

import (
	"encoding/json"
	"os"

	"github.com/containifyci/oauth2-storage/pkg/proto"
)

const (
	DefaultK8sSecret = "dunebot-token-storage"
)

type FileStorage struct {
	File string
}

type Storage interface {
	Load() (map[string]*proto.Installation, error)
	Save(tokens map[string]*proto.Installation) error
}

func NewFileStorage(file string) *FileStorage {
	return &FileStorage{
		File: file,
	}
}

func (s *FileStorage) Load() (map[string]*proto.Installation, error) {
	data, err := os.ReadFile(s.File)
	if err != nil {
		return nil, err
	}

	var tokens map[string]*proto.Installation
	err = json.Unmarshal(data, &tokens)
	return tokens, err
}

func (s *FileStorage) Save(tokens map[string]*proto.Installation) error {
	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}

	return os.WriteFile(s.File, data, 0644)
}

