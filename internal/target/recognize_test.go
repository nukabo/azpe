package target_test

import (
	"testing"

	"github.com/azpe/azpe/internal/target"
)

func TestClassifyTarget(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantType   target.TargetType
		wantFamily target.AzureServiceFamily
	}{
		{
			name:       "Key Vault",
			input:      "myvault.vault.azure.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyKeyVault,
		},
		{
			name:       "Managed HSM Key Vault",
			input:      "myhsm.managedhsm.azure.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyKeyVault,
		},
		{
			name:       "Storage Blob",
			input:      "mystorage.blob.core.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyStorageBlob,
		},
		{
			name:       "Storage DFS",
			input:      "mystorage.dfs.core.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyStorageDFS,
		},
		{
			name:       "Storage File",
			input:      "mystorage.file.core.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyStorageFile,
		},
		{
			name:       "Storage Queue",
			input:      "mystorage.queue.core.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyStorageQueue,
		},
		{
			name:       "Storage Table",
			input:      "mystorage.table.core.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyStorageTable,
		},
		{
			name:       "Storage Web",
			input:      "mystorage.web.core.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyStorageWeb,
		},
		{
			name:       "AI Search",
			input:      "mysearch.search.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyAISearch,
		},
		{
			name:       "Azure SQL",
			input:      "mydb.database.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilySQL,
		},
		{
			name:       "Cosmos DB Documents",
			input:      "mycosmos.documents.azure.com",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyCosmosDB,
		},
		{
			name:       "Cosmos DB Mongo",
			input:      "mycosmos.mongo.cosmos.azure.com",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyCosmosDB,
		},
		{
			name:       "Azure OpenAI",
			input:      "myaccount.openai.azure.com",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyAzureOpenAI,
		},
		{
			name:       "Azure Container Registry",
			input:      "myregistry.azurecr.io",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyContainerRegistry,
		},
		{
			name:       "App Configuration",
			input:      "myconfig.azconfig.io",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyAppConfiguration,
		},
		{
			name:       "Service Bus",
			input:      "mynamespace.servicebus.windows.net",
			wantType:   target.TargetTypeRecognizedAzure,
			wantFamily: target.FamilyServiceBus,
		},
		{
			name:       "Possible Azure generic domain",
			input:      "custom-service.azurewebsites.net",
			wantType:   target.TargetTypePossibleAzure,
			wantFamily: target.FamilyOtherAzure,
		},
		{
			name:       "Generic non-Azure microsoft.com",
			input:      "microsoft.com",
			wantType:   target.TargetTypeUnrecognized,
			wantFamily: target.FamilyNone,
		},
		{
			name:       "Generic non-Azure example.com",
			input:      "example.com",
			wantType:   target.TargetTypeUnrecognized,
			wantFamily: target.FamilyNone,
		},
		{
			name:       "Boundary safety attacker sub-domain",
			input:      "evil-vault.azure.net.attacker.example",
			wantType:   target.TargetTypeUnrecognized,
			wantFamily: target.FamilyNone,
		},
		{
			name:       "IPv4 literal",
			input:      "10.0.0.1",
			wantType:   target.TargetTypeIPLiteral,
			wantFamily: target.FamilyNone,
		},
		{
			name:       "IPv6 literal",
			input:      "fd00::1",
			wantType:   target.TargetTypeIPLiteral,
			wantFamily: target.FamilyNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotFamily := target.ClassifyTarget(tt.input)
			if gotType != tt.wantType {
				t.Errorf("ClassifyTarget(%q) type = %v, want %v", tt.input, gotType, tt.wantType)
			}
			if gotFamily != tt.wantFamily {
				t.Errorf("ClassifyTarget(%q) family = %v, want %v", tt.input, gotFamily, tt.wantFamily)
			}
		})
	}
}
