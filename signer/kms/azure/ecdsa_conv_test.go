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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawToDER(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			// Generate a key pair
			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			// Create a test digest
			digest := make([]byte, 32)
			_, err = rand.Read(digest)
			require.NoError(t, err)

			// Sign to get R and S
			r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
			require.NoError(t, err)

			// Create raw signature
			keySize := curveSize(curve)
			raw := make([]byte, 2*keySize)
			rBytes := r.Bytes()
			sBytes := s.Bytes()
			copy(raw[keySize-len(rBytes):keySize], rBytes)
			copy(raw[2*keySize-len(sBytes):], sBytes)

			// Convert to DER
			der, err := rawToDER(raw, curve)
			assert.NoError(t, err)

			// Verify DER format
			var sig ecdsaSignature
			_, err = asn1.Unmarshal(der, &sig)
			assert.NoError(t, err)
			assert.Equal(t, r, sig.R)
			assert.Equal(t, s, sig.S)
		})
	}
}

func TestDERToRaw(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			// Generate a key pair
			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			// Create a test digest
			digest := make([]byte, 32)
			_, err = rand.Read(digest)
			require.NoError(t, err)

			// Sign to get R and S
			r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
			require.NoError(t, err)

			// Create DER signature
			der, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
			require.NoError(t, err)

			// Convert to raw
			raw, err := derToRaw(der, curve)
			assert.NoError(t, err)

			// Verify raw format
			keySize := curveSize(curve)
			assert.Equal(t, 2*keySize, len(raw))

			// Extract R and S from raw
			rFromRaw := new(big.Int).SetBytes(raw[:keySize])
			sFromRaw := new(big.Int).SetBytes(raw[keySize:])

			assert.Equal(t, r, rFromRaw)
			assert.Equal(t, s, sFromRaw)
		})
	}
}

func TestRoundTripConversion(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			// Generate a key pair
			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			// Create a test digest
			digest := make([]byte, 32)
			_, err = rand.Read(digest)
			require.NoError(t, err)

			// Sign to get R and S
			r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
			require.NoError(t, err)

			// Create raw signature
			keySize := curveSize(curve)
			originalRaw := make([]byte, 2*keySize)
			rBytes := r.Bytes()
			sBytes := s.Bytes()
			copy(originalRaw[keySize-len(rBytes):keySize], rBytes)
			copy(originalRaw[2*keySize-len(sBytes):], sBytes)

			// Convert raw -> DER -> raw
			der, err := rawToDER(originalRaw, curve)
			require.NoError(t, err)

			raw, err := derToRaw(der, curve)
			require.NoError(t, err)

			assert.Equal(t, originalRaw, raw)

			// Also test DER -> raw -> DER
			originalDER, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
			require.NoError(t, err)

			raw2, err := derToRaw(originalDER, curve)
			require.NoError(t, err)

			der2, err := rawToDER(raw2, curve)
			require.NoError(t, err)

			assert.Equal(t, originalDER, der2)
		})
	}
}

func TestInvalidSignatureLengths(t *testing.T) {
	curve := elliptic.P256()
	keySize := curveSize(curve)

	// Test raw signature with wrong length
	wrongLengthRaw := make([]byte, 2*keySize-1)
	_, err := rawToDER(wrongLengthRaw, curve)
	assert.Error(t, err)

	// Test invalid DER
	invalidDER := []byte{0x30, 0x00}
	_, err = derToRaw(invalidDER, curve)
	assert.Error(t, err)
}

func TestCurveSize(t *testing.T) {
	tests := []struct {
		curve        elliptic.Curve
		expectedSize int
	}{
		{elliptic.P256(), 32},
		{elliptic.P384(), 48},
		{elliptic.P521(), 66},
	}

	for _, tt := range tests {
		t.Run(tt.curve.Params().Name, func(t *testing.T) {
			size := curveSize(tt.curve)
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}
