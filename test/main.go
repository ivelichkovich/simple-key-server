package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"k8s.io/key-server/test/claims"
	externalsigner "k8s.io/key-server/v1alpha1"
	"log"
	"path/filepath"
	"time"

	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func NewRemoteOpaqueSigner(client externalsigner.KeyServiceClient) *RemoteOpaqueSigner {
	return &RemoteOpaqueSigner{
		client: client,
	}
}

type RemoteOpaqueSigner struct {
	client externalsigner.KeyServiceClient
}

var _ jose.OpaqueSigner = &RemoteOpaqueSigner{}

func (s *RemoteOpaqueSigner) Public() *jose.JSONWebKey {
	resp, err := s.client.ListPublicKeys(context.Background(), &externalsigner.ListPublicKeysRequest{})
	if err != nil {
		log.Printf("Error getting public keys %v", err)
		return nil
	}
	var currentPublicKey *externalsigner.PublicKey
	for _, key := range resp.PublicKeys {
		if resp.ActiveKeyId == key.KeyId {
			currentPublicKey = key
			break
		}
	}
	if currentPublicKey == nil {
		log.Printf("Current key_id %s not found in list", resp.ActiveKeyId)
		return nil
	}

	response := &jose.JSONWebKey{
		KeyID:     currentPublicKey.KeyId,
		Algorithm: currentPublicKey.Algorithm,
		Use:       "sig",
	}

	// The rest of this function is taken care of by k8s libs in kubernetes
	block, _ := pem.Decode(currentPublicKey.PublicKey)
	if block == nil {
		log.Printf("Failed to parse PEM block containing the public key")
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("Error parsing public key %v", err)
		return nil
	}
	response.Key = pub

	var certificates []*x509.Certificate
	var certificateBytes []byte = currentPublicKey.Certificates
	for len(certificateBytes) > 0 {
		block, certificateBytes := pem.Decode(certificateBytes)
		if block == nil {
			log.Printf("Failed to parse PEM block containing x509 certificate")
			return nil
		}
		if len(certificateBytes) == 0 {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Error parsing x509 certificate %v", err)
			return nil
		}
		certificates = append(certificates, cert)
	}
	response.Certificates = certificates
	return response
}

func (s *RemoteOpaqueSigner) Algs() []jose.SignatureAlgorithm {
	resp, err := s.client.ListPublicKeys(context.Background(), &externalsigner.ListPublicKeysRequest{})
	if err != nil {
		log.Printf("Error getting public keys %v", err)
		return nil
	}
	algos := map[string]bool{}
	for _, key := range resp.PublicKeys {
		algos[key.Algorithm] = true
	}
	response := []jose.SignatureAlgorithm{}
	for alg := range algos {
		response = append(response, jose.SignatureAlgorithm(alg))
	}
	return response
}

func (s *RemoteOpaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	resp, err := s.client.SignPayload(context.Background(), &externalsigner.SignPayloadRequest{
		Payload:   payload,
		Algorithm: string(alg),
	})
	if err != nil {
		return nil, err
	}
	return resp.Content, nil
}

// ParsePublicKeysPEM is a helper function for reading an array of rsa.PublicKey or ecdsa.PublicKey from a PEM-encoded byte array.
// Reads public keys from both public and private key files.
func ParsePublicKeysPEM(keyData []byte) ([]interface{}, error) {
	var block *pem.Block
	keys := []interface{}{}
	for {
		// read the next block
		block, keyData = pem.Decode(keyData)
		if block == nil {
			break
		}

		if publicKey, err := parseRSAPublicKey(block.Bytes); err == nil {
			keys = append(keys, publicKey)
			continue
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("data does not contain any valid RSA or ECDSA public keys")
	}
	return keys, nil
}

// parseRSAPublicKey parses a single RSA public key from the provided data
func parseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(data); err != nil {
		if cert, err := x509.ParseCertificate(data); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	// Test if parsed key is an RSA Public Key
	var pubKey *rsa.PublicKey
	var ok bool
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("data doesn't contain valid RSA Public Key")
	}

	return pubKey, nil
}

func main() {
	socket := flag.String("socket", "./pipe.sock", "Unix socket to connect to")
	issuer := flag.String("issuer", "https://kubernetes.svc.default", "The Issuer for tokens")
	subject := flag.String("sub", "system:serviceaccount:default:default", "The subject")
	audienceNames := flag.StringSlice("aud", []string{"sts.amazonaws.com"}, "The audience for a token")

	flag.Parse()

	fullPath, err := filepath.Abs(*socket)
	if err != nil {
		log.Fatalf("failed to get abspath: %v", err)
	}

	address := fmt.Sprintf("unix://%s", fullPath)
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := externalsigner.NewKeyServiceClient(conn)

	// Example calling the API directly
	var keyData []byte

	ctx := context.Background()
	{
		op := "ListPublicKeys"
		resp, err := c.ListPublicKeys(ctx, &externalsigner.ListPublicKeysRequest{})
		if err != nil {
			log.Fatalf("%s() failed: %v", op, err)
		}
		log.Printf("%s response: %+v", op, resp)

		for _, pubKey := range resp.PublicKeys {
			keyData = append(keyData, pubKey.PublicKey...)
			keyData = append(keyData, '\n')
		}
	}
	{
		op := "SignPayload"
		resp, err := c.SignPayload(ctx, &externalsigner.SignPayloadRequest{
			Payload:   []byte(`{"sub": "micahhausler"}`),
			Algorithm: string(jose.RS256),
		})
		if err != nil {
			log.Fatalf("%s failed: %v", op, err)
		}
		log.Printf("%s response: %+v", op, resp)
	}

	// Example of what Kubernetes (the client) will do
	oSigner := NewRemoteOpaqueSigner(c)
	pub := oSigner.Public()
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(pub.Algorithm),
			Key:       oSigner,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderKey("kid"): pub.KeyID,
			},
		},
	)
	now := time.Now()
	pc := &claims.PrivateClaims{
		Kubernetes: claims.Kubernetes{
			Namespace: "default",
			Svcacct: claims.Ref{
				Name: "default",
				UID:  "63C011E0-5A34-4F45-9149-5EBE4B631514",
			},
			Pod: &claims.Ref{
				Name: "nginx",
				UID:  "13C011E0-5A34-4F45-9149-5EBE4B631514",
			},
		},
	}
	jwtToken := jwt.Signed(signer).
		Claims(&jwt.Claims{
			Issuer:    *issuer,
			Subject:   *subject,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(time.Duration(60*60*24) * time.Second)),
			Audience:  *audienceNames,
		}).
		Claims(pc)

	token, err := jwtToken.
		CompactSerialize()
	if err != nil {
		log.Fatalf("Token failed to sign: %v", err)
	}
	log.Printf("Token: %s", token)

	tok, err := jwtToken.Token()
	if err != nil {
		panic("Bad jwt token format")
	}

	out := jwt.Claims{}

	keys, err := ParsePublicKeysPEM(keyData)
	if err != nil {
		panic("not pem format")
	}

	var found bool
	for _, pk := range keys {
		if err := tok.Claims(pk, &out); err == nil {
			found = true
			log.Printf("Found public key match")
			break
		}
	}
	if !found {
		panic("none of the public keys match")
	}
	log.Printf("Tests pass!")
}
