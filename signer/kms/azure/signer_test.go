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
	"bytes"
	"crypto"
	"testing"

	"github.com/in-toto/go-witness/signer/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSignerVerifier(t *testing.T) {
	tests := []struct {
		name      string
		keyType   string
		hashFunc  crypto.Hash
		wantError bool
	}{
		{
			name:     "RSA key with SHA256",
			keyType:  "RSA",
			hashFunc: crypto.SHA256,
		},
		{
			name:     "EC key with SHA256",
			keyType:  "EC",
			hashFunc: crypto.SHA256,
		},
		{
			name:     "EC key with SHA384",
			keyType:  "EC",
			hashFunc: crypto.SHA384,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client
			fakeClient, err := newFakeAzureClient(tt.keyType)
			require.NoError(t, err)

			// Create KMS signer provider
			ksp := &kms.KMSSignerProvider{
				Reference: "azurekms://test-vault.vault.azure.net/test-key",
				HashFunc:  tt.hashFunc,
				Options: map[string]kms.KMSClientOptions{
					providerName: &azureClientOptions{},
				},
			}

			// Create signer verifier with fake client
			sv := &SignerVerifier{
				reference: ksp.Reference,
				client:    fakeClient,
				hashFunc:  tt.hashFunc,
			}

			// Test KeyID
			keyID, err := sv.KeyID()
			assert.NoError(t, err)
			assert.Equal(t, ksp.Reference, keyID)

			// Test signing and verification
			message := []byte("test message")
			reader := bytes.NewReader(message)

			// Sign
			sig, err := sv.Sign(reader)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, sig)

			// Verify
			reader.Seek(0, 0)
			err = sv.Verify(reader, sig)
			assert.NoError(t, err)

			// Test with wrong signature
			wrongSig := make([]byte, len(sig))
			copy(wrongSig, sig)
			wrongSig[0] ^= 0xFF
			reader.Seek(0, 0)
			err = sv.Verify(reader, wrongSig)
			assert.Error(t, err)
		})
	}
}

func TestSupportedAlgorithms(t *testing.T) {
	sv := &SignerVerifier{}
	algs := sv.SupportedAlgorithms()
	assert.NotEmpty(t, algs)
	assert.Contains(t, algs, "RS256")
	assert.Contains(t, algs, "ES256")
}

func TestDefaultAlgorithm(t *testing.T) {
	sv := &SignerVerifier{}
	alg := sv.DefaultAlgorithm()
	assert.Equal(t, "ES256", alg)
}
