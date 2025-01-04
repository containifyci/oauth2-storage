package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/containifyci/oauth2-storage/pkg/proto"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

type (
	K8sStorage struct {
		Clientset kubernetes.Interface
		Namespace string
	}

	K8sConfigReadder func() (*rest.Config, error)
)

func InClusterConfig() K8sConfigReadder {
	return func() (*rest.Config, error) {
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		return config, nil
	}
}

func NewK8sStorage(namespace string, k8sConfig K8sConfigReadder) (*K8sStorage, error) {
	config, err := k8sConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &K8sStorage{
		Clientset: clientset,
		Namespace: namespace,
	}, nil
}

func (s *K8sStorage) GetSecret() (*v1.Secret, error) {
	ctx := context.Background()
	api := s.Clientset.CoreV1()
	secret, err := api.Secrets(s.Namespace).Get(ctx, DefaultK8sSecret, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	} else if errors.IsNotFound(err) {
		return nil, nil
	}
	return secret, nil
}

func (s *K8sStorage) Load() (map[string]*proto.Installation, error) {
	secret, err := s.GetSecret()
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return make(map[string]*proto.Installation, 0), nil
	}

	secretData := secret.Data["tokens"]
	if len(secretData) > 0 {
		var tokens map[string]*proto.Installation
		err = json.Unmarshal(secretData, &tokens)
		return tokens, err
	}
	return make(map[string]*proto.Installation, 0), nil
}

func (s *K8sStorage) Save(tokens map[string]*proto.Installation) error {
	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}

	secret, err := s.GetSecret()
	if err != nil {
		return err
	}

	ctx := context.Background()
	api := s.Clientset.CoreV1()

	//create if the secret does not exist
	if secret == nil {
		_, err = api.Secrets(s.Namespace).Create(ctx, &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: DefaultK8sSecret,
			},
			Data: map[string][]byte{
				"tokens": []byte(data),
			},
		}, metav1.CreateOptions{})

		if err != nil {
			return err
		}
	} else { //update the secret if it exists already
		retryErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			currentSecret, err := api.Secrets(s.Namespace).Get(context.TODO(), DefaultK8sSecret, metav1.GetOptions{})
			if err != nil {
				return err
			}

			currentSecret.Data["date"] = []byte(time.Now().Format(time.RFC3339))
			currentSecret.Data["tokens"] = []byte(data)

			_, updateErr := api.Secrets(s.Namespace).Update(context.TODO(), currentSecret, metav1.UpdateOptions{})
			return updateErr
		})

		if retryErr != nil {
			return err
		}
	}

	return nil
}
