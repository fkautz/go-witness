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
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCloudInfo(t *testing.T) {
	tests := []struct {
		name        string
		vaultURL    string
		envValue    string
		wantName    string
		wantSuffix  string
		wantConfig  cloud.Configuration
		wantErr     bool
		errContains string
	}{
		{
			name:       "Public cloud from URL",
			vaultURL:   "https://my-vault.vault.azure.net/",
			wantName:   "AzurePublic",
			wantSuffix: ".vault.azure.net",
			wantConfig: cloud.AzurePublic,
		},
		{
			name:       "Government cloud from URL",
			vaultURL:   "https://my-vault.vault.usgovcloudapi.net/",
			wantName:   "AzureGovernment",
			wantSuffix: ".vault.usgovcloudapi.net",
			wantConfig: cloud.AzureGovernment,
		},
		{
			name:       "China cloud from URL",
			vaultURL:   "https://my-vault.vault.azure.cn/",
			wantName:   "AzureChina",
			wantSuffix: ".vault.azure.cn",
			wantConfig: cloud.AzureChina,
		},
		{
			name:        "Unknown cloud from URL",
			vaultURL:    "https://my-vault.vault.unknown.com/",
			wantErr:     true,
			errContains: "unable to determine cloud from vault URL",
		},
		{
			name:       "Environment variable overrides URL detection - public",
			vaultURL:   "https://my-vault.vault.azure.net/",
			envValue:   "AzurePublic",
			wantName:   "AzurePublic",
			wantSuffix: ".vault.azure.net",
			wantConfig: cloud.AzurePublic,
		},
		{
			name:       "Environment variable with lowercase",
			vaultURL:   "https://my-vault.vault.azure.net/",
			envValue:   "azurepublic",
			wantName:   "AzurePublic",
			wantSuffix: ".vault.azure.net",
			wantConfig: cloud.AzurePublic,
		},
		{
			name:       "Environment variable with alias - government",
			vaultURL:   "https://my-vault.vault.usgovcloudapi.net/",
			envValue:   "government",
			wantName:   "AzureGovernment",
			wantSuffix: ".vault.usgovcloudapi.net",
			wantConfig: cloud.AzureGovernment,
		},
		{
			name:       "Environment variable with alias - china",
			vaultURL:   "https://my-vault.vault.azure.cn/",
			envValue:   "china",
			wantName:   "AzureChina",
			wantSuffix: ".vault.azure.cn",
			wantConfig: cloud.AzureChina,
		},
		{
			name:        "Invalid environment variable",
			vaultURL:    "https://my-vault.vault.azure.net/",
			envValue:    "InvalidCloud",
			wantErr:     true,
			errContains: "unsupported Azure environment",
		},
		{
			name:        "Environment mismatch with URL",
			vaultURL:    "https://my-vault.vault.azure.net/",
			envValue:    "AzureChina",
			wantErr:     true,
			errContains: "doesn't match cloud",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore environment
			oldEnv := os.Getenv("AZURE_ENVIRONMENT")
			defer os.Setenv("AZURE_ENVIRONMENT", oldEnv)

			if tt.envValue != "" {
				os.Setenv("AZURE_ENVIRONMENT", tt.envValue)
			} else {
				os.Unsetenv("AZURE_ENVIRONMENT")
			}

			got, err := GetCloudInfo(tt.vaultURL)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.Name)
			assert.Equal(t, tt.wantSuffix, got.VaultDNSSuffix)
			assert.Equal(t, tt.wantConfig, got.Configuration)
		})
	}
}

func TestNormalizeCloudName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Public cloud variations
		{"public", "AzurePublic"},
		{"Public", "AzurePublic"},
		{"AZUREPUBLIC", "AzurePublic"},
		{"azurepublic", "AzurePublic"},
		{"AzureCloud", "AzurePublic"},
		{"azurecloud", "AzurePublic"},

		// Government cloud variations
		{"government", "AzureGovernment"},
		{"Government", "AzureGovernment"},
		{"AZUREGOVERNMENT", "AzureGovernment"},
		{"azuregovernment", "AzureGovernment"},
		{"AzureUSGov", "AzureGovernment"},
		{"azureusgov", "AzureGovernment"},
		{"AzureUSGovernment", "AzureGovernment"},
		{"azureusgovernment", "AzureGovernment"},

		// China cloud variations
		{"china", "AzureChina"},
		{"China", "AzureChina"},
		{"AZURECHINA", "AzureChina"},
		{"azurechina", "AzureChina"},
		{"AzureChinaCloud", "AzureChina"},
		{"azurechinacloud", "AzureChina"},

		// With spaces
		{" public ", "AzurePublic"},
		{"  government  ", "AzureGovernment"},
		{" china", "AzureChina"},

		// Unknown values pass through
		{"UnknownCloud", "unknowncloud"},
		{"CustomCloud", "customcloud"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeCloudName(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestGetClientOptions(t *testing.T) {
	tests := []struct {
		name      string
		cloudInfo CloudInfo
	}{
		{
			name: "Public cloud options",
			cloudInfo: CloudInfo{
				Name:          "AzurePublic",
				Configuration: cloud.AzurePublic,
			},
		},
		{
			name: "Government cloud options",
			cloudInfo: CloudInfo{
				Name:          "AzureGovernment",
				Configuration: cloud.AzureGovernment,
			},
		},
		{
			name: "China cloud options",
			cloudInfo: CloudInfo{
				Name:          "AzureChina",
				Configuration: cloud.AzureChina,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := GetClientOptions(tt.cloudInfo)
			assert.Equal(t, tt.cloudInfo.Configuration, opts.Cloud)
		})
	}
}

func TestValidateVaultURLForCloud(t *testing.T) {
	tests := []struct {
		name     string
		vaultURL string
		cloud    CloudInfo
		wantErr  bool
	}{
		{
			name:     "Valid public cloud URL",
			vaultURL: "https://my-vault.vault.azure.net/",
			cloud:    SupportedClouds["AzurePublic"],
			wantErr:  false,
		},
		{
			name:     "Valid government cloud URL",
			vaultURL: "https://my-vault.vault.usgovcloudapi.net/",
			cloud:    SupportedClouds["AzureGovernment"],
			wantErr:  false,
		},
		{
			name:     "Valid China cloud URL",
			vaultURL: "https://my-vault.vault.azure.cn/",
			cloud:    SupportedClouds["AzureChina"],
			wantErr:  false,
		},
		{
			name:     "Case insensitive match",
			vaultURL: "HTTPS://MY-VAULT.VAULT.AZURE.NET/",
			cloud:    SupportedClouds["AzurePublic"],
			wantErr:  false,
		},
		{
			name:     "Mismatched URL and cloud",
			vaultURL: "https://my-vault.vault.azure.net/",
			cloud:    SupportedClouds["AzureChina"],
			wantErr:  true,
		},
		{
			name:     "Government URL with China cloud",
			vaultURL: "https://my-vault.vault.usgovcloudapi.net/",
			cloud:    SupportedClouds["AzureChina"],
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVaultURLForCloud(tt.vaultURL, tt.cloud)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
