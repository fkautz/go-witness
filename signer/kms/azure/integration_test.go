//go:build integration
// +build integration

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
	"context"
	"os"
	"testing"

	"github.com/in-toto/go-witness/signer/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureKMSIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("AZURE_KMS_INTEGRATION_TEST") != "1" {
		t.Skip("Skipping Azure KMS integration test. Set AZURE_KMS_INTEGRATION_TEST=1 to run.")
	}

	// Check for required environment variables
	vaultName := os.Getenv("AZURE_KMS_VAULT_NAME")
	keyName := os.Getenv("AZURE_KMS_KEY_NAME")

	if vaultName == "" || keyName == "" {
		t.Skip("AZURE_KMS_VAULT_NAME and AZURE_KMS_KEY_NAME must be set for integration tests")
	}

	ctx := context.Background()
	ref := "azurekms://" + vaultName + ".vault.azure.net/" + keyName

	// Create KMS signer provider
	ksp := kms.New(
		kms.WithRef(ref),
		kms.WithHash("SHA256"),
	)

	// Create signer
	signer, err := ksp.Signer(ctx)
	require.NoError(t, err, "Failed to create Azure KMS signer")

	// Test signing
	message := []byte("integration test message")
	reader := bytes.NewReader(message)

	sig, err := signer.Sign(reader)
	require.NoError(t, err, "Failed to sign message")
	assert.NotEmpty(t, sig, "Signature should not be empty")

	// Test verification
	verifier, err := signer.Verifier()
	require.NoError(t, err, "Failed to get verifier")

	reader.Seek(0, 0)
	err = verifier.Verify(reader, sig)
	assert.NoError(t, err, "Failed to verify signature")

	// Test with wrong signature
	wrongSig := make([]byte, len(sig))
	copy(wrongSig, sig)
	wrongSig[0] ^= 0xFF

	reader.Seek(0, 0)
	err = verifier.Verify(reader, wrongSig)
	assert.Error(t, err, "Verification should fail with wrong signature")
}

func TestAzureKMSRemoteVerify(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("AZURE_KMS_INTEGRATION_TEST") != "1" {
		t.Skip("Skipping Azure KMS integration test. Set AZURE_KMS_INTEGRATION_TEST=1 to run.")
	}

	vaultName := os.Getenv("AZURE_KMS_VAULT_NAME")
	keyName := os.Getenv("AZURE_KMS_KEY_NAME")

	if vaultName == "" || keyName == "" {
		t.Skip("AZURE_KMS_VAULT_NAME and AZURE_KMS_KEY_NAME must be set for integration tests")
	}

	ctx := context.Background()
	ref := "azurekms://" + vaultName + ".vault.azure.net/" + keyName

	// Test with remote verification enabled (default)
	t.Run("Remote Verification", func(t *testing.T) {
		ksp := kms.New(
			kms.WithRef(ref),
			kms.WithHash("SHA256"),
		)

		signer, err := ksp.Signer(ctx)
		require.NoError(t, err)

		message := []byte("remote verify test")
		reader := bytes.NewReader(message)

		sig, err := signer.Sign(reader)
		require.NoError(t, err)

		verifier, err := signer.Verifier()
		require.NoError(t, err)

		reader.Seek(0, 0)
		err = verifier.Verify(reader, sig)
		assert.NoError(t, err)
	})

	// Test with local verification
	t.Run("Local Verification", func(t *testing.T) {
		// Need to set the option through the provider options
		ksp := kms.New(
			kms.WithRef(ref),
			kms.WithHash("SHA256"),
		)

		// Set remote verify to false
		if azOpts, ok := ksp.Options[providerName].(*azureClientOptions); ok {
			azOpts.verifyRemotely = false
		}

		signer, err := ksp.Signer(ctx)
		require.NoError(t, err)

		message := []byte("local verify test")
		reader := bytes.NewReader(message)

		sig, err := signer.Sign(reader)
		require.NoError(t, err)

		verifier, err := signer.Verifier()
		require.NoError(t, err)

		reader.Seek(0, 0)
		err = verifier.Verify(reader, sig)
		assert.NoError(t, err)
	})
}
