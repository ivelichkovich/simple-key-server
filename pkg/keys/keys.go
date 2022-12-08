package keys

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	externalsigner "k8s.io/key-server/v1alpha1"
	"k8s.io/klog/v2"
	"sync"
)

// Handle operations on signing key pair
type Keys struct {
	privateKey *rsa.PrivateKey
	publicKeys map[string][]byte
	mutex      sync.RWMutex
}

// Creates new keys
func NewKeys(privateKey *rsa.PrivateKey, publicKeys map[string][]byte) Keys {
	return Keys{
		privateKey: privateKey,
		publicKeys: publicKeys,
		mutex:      sync.RWMutex{},
	}
}

// Update key pair
func (k *Keys) UpdateKeys(privateKey *rsa.PrivateKey, publicKeys map[string][]byte) {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.privateKey = privateKey
	k.publicKeys = publicKeys
}

// all read access to Keys.privateKey and Keys.publicKeys are exposed in this method, guarded by mutex.
func (k *Keys) readKeys() (*rsa.PrivateKey, map[string][]byte) {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	return k.privateKey, k.publicKeys
}

func getPubKeyBytes(pk *rsa.PrivateKey) ([]byte, error) {
	if pk == nil {
		return nil, fmt.Errorf("No private key!")
	}
	return pubKeyPKIX(&pk.PublicKey)
}

func pubKeyPKIX(kU *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(kU)
	if err != nil {
		return nil, errors.Wrap(err, "Could not marshal public key")
	}
	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(&block), nil
}

// for simplicity purposes, KeyID is the sha1sum(PKIX(pubkey))
func keyId(kU *rsa.PublicKey) (string, error) {
	data, err := pubKeyPKIX(kU)
	if err != nil {
		return "", errors.Wrap(err, "Could not encode key")
	}
	return fmt.Sprintf("%x", sha1.Sum(data)), nil
}

// whether keys are available
func (k *Keys) KeysAvailable() bool {
	privateKey, publicKeys := k.readKeys()
	return privateKey != nil && publicKeys != nil && len(publicKeys) > 0
}

// Sign payload
func (k *Keys) SignPayload(ctx context.Context, req *externalsigner.SignPayloadRequest) (*externalsigner.SignPayloadResponse, error) {
	klog.Infof("Sign Payload")
	// TODO switch on SignPayloadRequest Algorithm?
	privateKey, _ := k.readKeys()

	signer := cryptosigner.Opaque(privateKey)

	signedData, err := signer.SignPayload(req.Payload, jose.SignatureAlgorithm(req.Algorithm))
	if err != nil {
		klog.Errorf("failed to Sign payload. %v", err.Error())
		return nil, errors.Wrap(err, "Signer failed to sign payload")
	}

	klog.V(4).Infof("Signed Payload: %v", signedData)

	return &externalsigner.SignPayloadResponse{
		Content: signedData,
	}, nil
}

// List public keys
func (k *Keys) ListPublicKeys(ctx context.Context, req *externalsigner.ListPublicKeysRequest) (*externalsigner.ListPublicKeysResponse, error) {
	klog.Infof("List Public Keys")
	privateKey, publicKeys := k.readKeys()

	kU, err := getPubKeyBytes(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get the public part of the private key")
	}

	// TODO: use the key IDs that're passed in, instead of regenerationg again.
	kid, err := keyId(&privateKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate the kid")
	}

	keys := []*externalsigner.PublicKey{
		{
			PublicKey:    kU,
			Certificates: nil,
			KeyId:        kid,
			Algorithm:    string(jose.RS256), // This is the signing algorithm client should be passing in SignPayload
		},
	}
	for pkid, kData := range publicKeys {
		keys = append(keys, &externalsigner.PublicKey{
			PublicKey:    kData,
			Certificates: nil,
			KeyId:        pkid,
			Algorithm:    string(jose.RS256),
		})
	}

	return &externalsigner.ListPublicKeysResponse{
		ActiveKeyId: kid,
		PublicKeys:  keys,
	}, nil
}
