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
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

// CloudInfo represents cloud-specific information
type CloudInfo struct {
	Name           string
	Configuration  cloud.Configuration
	VaultDNSSuffix string
}

// SupportedClouds maps cloud names to their configurations
var SupportedClouds = map[string]CloudInfo{
	"AzurePublic": {
		Name:           "AzurePublic",
		Configuration:  cloud.AzurePublic,
		VaultDNSSuffix: ".vault.azure.net",
	},
	"AzureGovernment": {
		Name:           "AzureGovernment",
		Configuration:  cloud.AzureGovernment,
		VaultDNSSuffix: ".vault.usgovcloudapi.net",
	},
	"AzureChina": {
		Name:           "AzureChina",
		Configuration:  cloud.AzureChina,
		VaultDNSSuffix: ".vault.azure.cn",
	},
}

// GetCloudInfo returns cloud information based on AZURE_ENVIRONMENT or vault URL
func GetCloudInfo(vaultURL string) (CloudInfo, error) {
	// First check environment variable
	if envName := os.Getenv("AZURE_ENVIRONMENT"); envName != "" {
		cloudInfo, err := getCloudByName(envName)
		if err != nil {
			return CloudInfo{}, err
		}
		// Validate the vault URL matches the cloud
		if err := validateVaultURLForCloud(vaultURL, cloudInfo); err != nil {
			return CloudInfo{}, err
		}
		return cloudInfo, nil
	}

	// Otherwise, detect from vault URL
	return getCloudFromVaultURL(vaultURL)
}

// GetClientOptions returns azcore.ClientOptions configured for the specified cloud
func GetClientOptions(cloudInfo CloudInfo) azcore.ClientOptions {
	return azcore.ClientOptions{
		Cloud: cloudInfo.Configuration,
	}
}

// getCloudByName returns cloud info for a given cloud name
func getCloudByName(name string) (CloudInfo, error) {
	// Normalize the name
	name = normalizeCloudName(name)

	for key, info := range SupportedClouds {
		if strings.EqualFold(key, name) {
			return info, nil
		}
	}

	return CloudInfo{}, fmt.Errorf("unsupported Azure environment: %s. Supported: AzurePublic, AzureGovernment, AzureChina", name)
}

// getCloudFromVaultURL determines cloud from vault URL
func getCloudFromVaultURL(vaultURL string) (CloudInfo, error) {
	vaultURL = strings.ToLower(vaultURL)

	for _, info := range SupportedClouds {
		if strings.Contains(vaultURL, info.VaultDNSSuffix) {
			return info, nil
		}
	}

	return CloudInfo{}, fmt.Errorf("unable to determine cloud from vault URL: %s", vaultURL)
}

// normalizeCloudName normalizes common cloud name variations
func normalizeCloudName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)

	switch name {
	case "public", "azurepublic", "azurecloud":
		return "AzurePublic"
	case "government", "azuregovernment", "azureusgov", "azureusgovernment":
		return "AzureGovernment"
	case "china", "azurechina", "azurechinacloud":
		return "AzureChina"
	default:
		return name
	}
}

// validateVaultURLForCloud checks if vault URL matches the cloud
func validateVaultURLForCloud(vaultURL string, cloud CloudInfo) error {
	if !strings.Contains(strings.ToLower(vaultURL), cloud.VaultDNSSuffix) {
		return fmt.Errorf("vault URL %s doesn't match cloud %s (expected suffix: %s)", 
			vaultURL, cloud.Name, cloud.VaultDNSSuffix)
	}
	return nil
}