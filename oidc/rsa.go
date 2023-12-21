package oidc

import (
	"crypto/rsa"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type rsaKeys struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
}

// newRSAKeys(publicKeyPath, privateKeyPath)
func newRSAKeys(publicKeyPath string, privateKeyPath string) (*rsaKeys, error) {
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

	return &rsaKeys{
		verifyKey: verifyKey,
		signKey:   signKey,
	}, nil
}
