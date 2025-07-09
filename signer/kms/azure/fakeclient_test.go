// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/signer/kms"
)

// fakeAzureClient is a mock client for testing
type fakeAzureClient struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	keyType    azkeys.KeyType
	hashFunc   crypto.Hash
	options    *azureClientOptions
}

func newFakeAzureClient(keyType string) (*fakeAzureClient, error) {
	f := &fakeAzureClient{
		options: &azureClientOptions{
			verifyRemotely: true,
		},
	}

	switch keyType {
	case "RSA":
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		f.privateKey = privKey
		f.publicKey = &privKey.PublicKey
		f.keyType = azkeys.KeyTypeRSA
		f.hashFunc = crypto.SHA256
	case "EC":
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		f.privateKey = privKey
		f.publicKey = &privKey.PublicKey
		f.keyType = azkeys.KeyTypeEC
		f.hashFunc = crypto.SHA256
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	return f, nil
}

func (f *fakeAzureClient) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	return f.hashFunc, nil
}

func (f *fakeAzureClient) sign(ctx context.Context, digest []byte, hash crypto.Hash) ([]byte, error) {
	switch key := f.privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		// Return in ASN.1 DER format
		return asn1.Marshal(ecdsaSignature{R: r, S: s})
	default:
		return nil, errors.New("unsupported key type")
	}
}

func (f *fakeAzureClient) verify(ctx context.Context, sig, message io.Reader) error {
	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return err
	}

	// Compute digest
	digest, _, err := cryptoutil.ComputeDigest(message, f.hashFunc, azureSupportedHashFuncs)
	if err != nil {
		return err
	}

	switch key := f.publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, f.hashFunc, digest, sigBytes)
	case *ecdsa.PublicKey:
		// Try both DER and raw formats
		if verifyECDSASignature(key, digest, sigBytes) {
			return nil
		}
		return errors.New("signature verification failed")
	default:
		return errors.New("unsupported key type")
	}
}

func (f *fakeAzureClient) setupClient(ctx context.Context, ksp *kms.KMSSignerProvider) error {
	// Extract options from ksp if provided
	if ksp != nil && ksp.Options != nil {
		for _, opt := range ksp.Options {
			if azOpt, ok := opt.(*azureClientOptions); ok {
				f.options = azOpt
				break
			}
		}
	}
	return nil
}

func (f *fakeAzureClient) fetchKey(ctx context.Context) (*azkeys.KeyBundle, error) {
	jwk := &azkeys.JSONWebKey{
		Kty: &f.keyType,
	}

	switch key := f.publicKey.(type) {
	case *rsa.PublicKey:
		// jwk.N and jwk.E expect []byte
		jwk.N = key.N.Bytes()
		jwk.E = big.NewInt(int64(key.E)).Bytes()
	case *ecdsa.PublicKey:
		// jwk.X and jwk.Y expect []byte
		jwk.X = key.X.Bytes()
		jwk.Y = key.Y.Bytes()
		crv := azkeys.CurveNameP256
		jwk.Crv = &crv
	}

	return &azkeys.KeyBundle{
		Key: jwk,
	}, nil
}

func (f *fakeAzureClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return f.publicKey, nil
}
