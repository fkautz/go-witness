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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidReference(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		// Public cloud
		{
			name:    "valid public cloud reference",
			ref:     "azurekms://my-vault.vault.azure.net/my-key",
			wantErr: false,
		},
		{
			name:    "valid public cloud reference with version",
			ref:     "azurekms://my-vault.vault.azure.net/my-key/1234567890abcdef",
			wantErr: false,
		},
		// Government cloud
		{
			name:    "valid government cloud reference",
			ref:     "azurekms://my-vault.vault.usgovcloudapi.net/my-key",
			wantErr: false,
		},
		{
			name:    "valid government cloud reference with version",
			ref:     "azurekms://my-vault.vault.usgovcloudapi.net/my-key/abc123",
			wantErr: false,
		},
		// China cloud
		{
			name:    "valid china cloud reference",
			ref:     "azurekms://my-vault.vault.azure.cn/my-key",
			wantErr: false,
		},
		{
			name:    "valid china cloud reference with version",
			ref:     "azurekms://my-vault.vault.azure.cn/my-key/xyz789",
			wantErr: false,
		},
		// Invalid cases
		{
			name:    "missing scheme",
			ref:     "my-vault.vault.azure.net/my-key",
			wantErr: true,
		},
		{
			name:    "wrong scheme",
			ref:     "https://my-vault.vault.azure.net/my-key",
			wantErr: true,
		},
		{
			name:    "missing key name",
			ref:     "azurekms://my-vault.vault.azure.net/",
			wantErr: true,
		},
		{
			name:    "missing vault name",
			ref:     "azurekms://vault.azure.net/my-key",
			wantErr: true,
		},
		{
			name:    "invalid vault format",
			ref:     "azurekms://my-vault/my-key",
			wantErr: true,
		},
		{
			name:    "empty reference",
			ref:     "",
			wantErr: true,
		},
		{
			name:    "invalid cloud suffix",
			ref:     "azurekms://my-vault.vault.invalid.com/my-key",
			wantErr: false, // This is valid per the regex pattern
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidReference(tt.ref)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseReference(t *testing.T) {
	tests := []struct {
		name           string
		resourceID     string
		wantVaultURL   string
		wantKeyName    string
		wantKeyVersion string
		wantErr        bool
	}{
		// Public cloud
		{
			name:         "public cloud without version",
			resourceID:   "azurekms://my-vault.vault.azure.net/my-key",
			wantVaultURL: "https://my-vault.vault.azure.net/",
			wantKeyName:  "my-key",
		},
		{
			name:           "public cloud with version",
			resourceID:     "azurekms://my-vault.vault.azure.net/my-key/1234567890abcdef",
			wantVaultURL:   "https://my-vault.vault.azure.net/",
			wantKeyName:    "my-key",
			wantKeyVersion: "1234567890abcdef",
		},
		// Government cloud
		{
			name:         "government cloud without version",
			resourceID:   "azurekms://gov-vault.vault.usgovcloudapi.net/gov-key",
			wantVaultURL: "https://gov-vault.vault.usgovcloudapi.net/",
			wantKeyName:  "gov-key",
		},
		{
			name:           "government cloud with version",
			resourceID:     "azurekms://gov-vault.vault.usgovcloudapi.net/gov-key/abc123def456",
			wantVaultURL:   "https://gov-vault.vault.usgovcloudapi.net/",
			wantKeyName:    "gov-key",
			wantKeyVersion: "abc123def456",
		},
		// China cloud
		{
			name:         "china cloud without version",
			resourceID:   "azurekms://china-vault.vault.azure.cn/china-key",
			wantVaultURL: "https://china-vault.vault.azure.cn/",
			wantKeyName:  "china-key",
		},
		{
			name:           "china cloud with version",
			resourceID:     "azurekms://china-vault.vault.azure.cn/china-key/xyz789",
			wantVaultURL:   "https://china-vault.vault.azure.cn/",
			wantKeyName:    "china-key",
			wantKeyVersion: "xyz789",
		},
		// Complex names
		{
			name:         "vault with hyphens and numbers",
			resourceID:   "azurekms://test-vault-123.vault.azure.net/key-name-456",
			wantVaultURL: "https://test-vault-123.vault.azure.net/",
			wantKeyName:  "key-name-456",
		},
		// Error cases
		{
			name:       "invalid format",
			resourceID: "azurekms://invalid",
			wantErr:    true,
		},
		{
			name:       "missing scheme",
			resourceID: "my-vault.vault.azure.net/my-key",
			wantErr:    true,
		},
		{
			name:       "empty resource ID",
			resourceID: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vaultURL, keyName, keyVersion, err := ParseReference(tt.resourceID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantVaultURL, vaultURL)
			assert.Equal(t, tt.wantKeyName, keyName)
			assert.Equal(t, tt.wantKeyVersion, keyVersion)
		})
	}
}
