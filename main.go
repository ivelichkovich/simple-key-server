package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"k8s.io/key-server/pkg/keys"
	externalsigner "k8s.io/key-server/v1alpha1"
	"k8s.io/klog/v2"
	"net"
	"os"
	"syscall"
)

const (
	// RSAPrivateKeyBlockType is a possible value for pem.Block.Type.
	RSAPrivateKeyBlockType = "RSA PRIVATE KEY"
	// PrivateKeyBlockType is a possible value for pem.Block.Type.
	PrivateKeyBlockType = "PRIVATE KEY"
)

func main() {
	socket := flag.String("socket", "./pipe.sock", "Unix socket to listen on")
	privateKeyPath := flag.String("private-key", "./private-key.rsa", "Path to private key for signing")
	publicKeyPath := flag.String("public-key", "./key.pub", "Path to public key")

	privateKey := getPrivateKey(*privateKeyPath)
	publicKeys := getPublicKeys(*publicKeyPath)

	keys := keys.NewKeys(privateKey, publicKeys)

	err := syscall.Unlink(*socket)
	if err != nil {
		if err.Error() != "no such file or directory" {
			klog.Warningf("Failed to unlink unix socket. %v", err.Error())
		}
	}

	lis, err := net.Listen("unix", *socket)
	if err != nil {
		klog.Fatalf("failed to listen on unix socket: %v", err)
	}
	klog.Infof("Listening on unix socket %v", *socket)

	grpcServer := grpc.NewServer()

	externalsigner.RegisterKeyServiceServer(grpcServer, &keys)
	reflection.Register(grpcServer)
	if err := grpcServer.Serve(lis); err != nil {
		klog.Fatalf("failed to serve: %v", err)
	}
}

func getPrivateKey(path string) *rsa.PrivateKey {
	data, err := os.ReadFile(path)
	if err != nil {
		klog.Fatalf("error opening private key file: %v", err.Error())
	}

	var privateKeyPemBlock *pem.Block
	privateKeyPemBlock, _ = pem.Decode(data)

	var privateKey *rsa.PrivateKey
	var key interface{}
	switch privateKeyPemBlock.Type {
	case RSAPrivateKeyBlockType:
		klog.Infof("RSA Private Key Block Type")
		// RSA Private Key in PKCS#1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyPemBlock.Bytes)
	case PrivateKeyBlockType:
		klog.Infof("Private Key Block Type")
		// RSA or ECDSA Private Key in unencrypted PKCS#8 format
		key, err = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		switch key := key.(type) {
		case *rsa.PrivateKey:
			privateKey = key
		default:
			klog.Errorf("Private Key Parse Error - Private Key Block Type")
			err = fmt.Errorf("Only rsa private key is expected %s\n", privateKeyPemBlock.Type)
		}
	default:
		klog.Errorf("Private Key Parse Error, unexpected")
		err = fmt.Errorf("Unexpected private key type %s\n", privateKeyPemBlock.Type)
	}
	return privateKey
}

func getPublicKeys(path string) map[string][]byte {
	result := map[string][]byte{}
	data, err := os.ReadFile(path)
	if err != nil {
		klog.Fatalf("error opening public key file: %v", err.Error())
	}
	kid := fmt.Sprintf("%x", sha1.Sum(data))
	result[kid] = data
	return result
}
