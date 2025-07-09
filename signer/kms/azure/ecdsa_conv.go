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
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// ecdsaSignature represents an ECDSA signature in ASN.1 format
type ecdsaSignature struct {
	R, S *big.Int
}

// rawToDER converts an ECDSA signature from raw R||S format to ASN.1 DER format
func rawToDER(sig []byte, curve elliptic.Curve) ([]byte, error) {
	keySize := curveSize(curve)
	if len(sig) != 2*keySize {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", 2*keySize, len(sig))
	}

	// Split signature into R and S
	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])

	// Encode as ASN.1 DER
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

// derToRaw converts an ECDSA signature from ASN.1 DER format to raw R||S format
func derToRaw(sig []byte, curve elliptic.Curve) ([]byte, error) {
	var esig ecdsaSignature
	_, err := asn1.Unmarshal(sig, &esig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DER signature: %w", err)
	}

	if esig.R == nil || esig.S == nil {
		return nil, errors.New("invalid signature: R or S is nil")
	}

	keySize := curveSize(curve)

	// Pad R and S to the correct size
	rBytes := esig.R.Bytes()
	sBytes := esig.S.Bytes()

	raw := make([]byte, 2*keySize)

	// Copy R, padding with zeros on the left if necessary
	copy(raw[keySize-len(rBytes):keySize], rBytes)

	// Copy S, padding with zeros on the left if necessary
	copy(raw[2*keySize-len(sBytes):], sBytes)

	return raw, nil
}

// curveSize returns the key size in bytes for the given elliptic curve
func curveSize(curve elliptic.Curve) int {
	bitSize := curve.Params().BitSize
	return (bitSize + 7) / 8
}

// verifyECDSASignature is a helper function to verify ECDSA signatures
// It handles both DER and raw formats
func verifyECDSASignature(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	// Try DER format first
	var esig ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &esig); err == nil {
		return ecdsa.Verify(pub, hash, esig.R, esig.S)
	}

	// Try raw format
	keySize := curveSize(pub.Curve)
	if len(sig) == 2*keySize {
		r := new(big.Int).SetBytes(sig[:keySize])
		s := new(big.Int).SetBytes(sig[keySize:])
		return ecdsa.Verify(pub, hash, r, s)
	}

	return false
}
