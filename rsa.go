package main

import (
	"crypto/rsa"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type rsaProcessor struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
}

// newRSAProcessor(publicKeyPath, privateKeyPath)
func newRSAProcessor(publicKeyPath string, privateKeyPath string) (*rsaProcessor, error) {
	verifyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return nil, err
	}

	signBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return nil, err
	}

	return &rsaProcessor{
		verifyKey: verifyKey,
		signKey:   signKey,
	}, nil
}
