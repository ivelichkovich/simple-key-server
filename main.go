package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"k8s.io/key-server/pkg/keys"
	externalsigner "k8s.io/key-server/v1alpha1"
	"k8s.io/klog/v2"
	"net"
	"os"
	"syscall"
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
	block, _ := pem.Decode(data)
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		klog.Fatalf("error parsing private key: %v", err.Error())
	}
	key := parseResult.(*rsa.PrivateKey)
	return key
}

func getPublicKeys(path string) map[string][]byte {
	result := map[string][]byte{}
	data, err := os.ReadFile(path)
	if err != nil {
		klog.Fatalf("error opening public key file: %v", err.Error())
	}
	result["a811d89ef50c5f03c30745155ce76eadd117449"] = data
	return result
}
