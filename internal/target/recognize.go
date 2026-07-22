package target

import (
	"net/netip"
	"strings"
)

// TargetType represents the classification of the target input string.
type TargetType string

const (
	TargetTypeRecognizedAzure TargetType = "RECOGNIZED_AZURE_SERVICE"
	TargetTypePossibleAzure   TargetType = "POSSIBLE_AZURE_SERVICE"
	TargetTypeUnrecognized    TargetType = "UNRECOGNIZED_TARGET"
	TargetTypeIPLiteral       TargetType = "IP_LITERAL"
)

func (t TargetType) String() string {
	return string(t)
}

// AzureServiceFamily represents the identified Azure service family.
type AzureServiceFamily string

const (
	FamilyKeyVault          AzureServiceFamily = "KEY_VAULT"
	FamilyStorageBlob       AzureServiceFamily = "STORAGE_BLOB"
	FamilyStorageDFS        AzureServiceFamily = "STORAGE_DFS"
	FamilyStorageFile       AzureServiceFamily = "STORAGE_FILE"
	FamilyStorageQueue      AzureServiceFamily = "STORAGE_QUEUE"
	FamilyStorageTable      AzureServiceFamily = "STORAGE_TABLE"
	FamilyStorageWeb        AzureServiceFamily = "STORAGE_WEB"
	FamilyAISearch          AzureServiceFamily = "AI_SEARCH"
	FamilySQL               AzureServiceFamily = "SQL"
	FamilyCosmosDB          AzureServiceFamily = "COSMOS_DB"
	FamilyAzureOpenAI       AzureServiceFamily = "AZURE_OPENAI"
	FamilyContainerRegistry AzureServiceFamily = "CONTAINER_REGISTRY"
	FamilyAppConfiguration  AzureServiceFamily = "APP_CONFIGURATION"
	FamilyServiceBus        AzureServiceFamily = "SERVICE_BUS"
	FamilyOtherAzure        AzureServiceFamily = "OTHER_AZURE"
	FamilyNone              AzureServiceFamily = "NONE"
)

func (f AzureServiceFamily) String() string {
	return string(f)
}

// DisplayName returns a human-friendly string for the Azure service family.
func (f AzureServiceFamily) DisplayName() string {
	switch f {
	case FamilyKeyVault:
		return "Key Vault"
	case FamilyStorageBlob:
		return "Storage (Blob)"
	case FamilyStorageDFS:
		return "Storage (Data Lake Gen2 / DFS)"
	case FamilyStorageFile:
		return "Storage (File)"
	case FamilyStorageQueue:
		return "Storage (Queue)"
	case FamilyStorageTable:
		return "Storage (Table)"
	case FamilyStorageWeb:
		return "Storage (Static Web)"
	case FamilyAISearch:
		return "Azure AI Search"
	case FamilySQL:
		return "Azure SQL Database"
	case FamilyCosmosDB:
		return "Azure Cosmos DB"
	case FamilyAzureOpenAI:
		return "Azure OpenAI"
	case FamilyContainerRegistry:
		return "Azure Container Registry"
	case FamilyAppConfiguration:
		return "Azure App Configuration"
	case FamilyServiceBus:
		return "Azure Service Bus / Event Hubs"
	case FamilyOtherAzure:
		return "Azure Service"
	default:
		return "Unknown Service"
	}
}

type servicePattern struct {
	suffix string
	family AzureServiceFamily
}

var recognizedPatterns = []servicePattern{
	{suffix: ".vault.azure.net", family: FamilyKeyVault},
	{suffix: ".managedhsm.azure.net", family: FamilyKeyVault},
	{suffix: ".blob.core.windows.net", family: FamilyStorageBlob},
	{suffix: ".dfs.core.windows.net", family: FamilyStorageDFS},
	{suffix: ".file.core.windows.net", family: FamilyStorageFile},
	{suffix: ".queue.core.windows.net", family: FamilyStorageQueue},
	{suffix: ".table.core.windows.net", family: FamilyStorageTable},
	{suffix: ".web.core.windows.net", family: FamilyStorageWeb},
	{suffix: ".search.windows.net", family: FamilyAISearch},
	{suffix: ".database.windows.net", family: FamilySQL},
	{suffix: ".documents.azure.com", family: FamilyCosmosDB},
	{suffix: ".mongo.cosmos.azure.com", family: FamilyCosmosDB},
	{suffix: ".cassandra.cosmos.azure.com", family: FamilyCosmosDB},
	{suffix: ".gremlin.cosmos.azure.com", family: FamilyCosmosDB},
	{suffix: ".table.cosmos.azure.com", family: FamilyCosmosDB},
	{suffix: ".openai.azure.com", family: FamilyAzureOpenAI},
	{suffix: ".azurecr.io", family: FamilyContainerRegistry},
	{suffix: ".azconfig.io", family: FamilyAppConfiguration},
	{suffix: ".servicebus.windows.net", family: FamilyServiceBus},
}

var possibleAzureDomains = []string{
	".azure.com",
	".azure.net",
	".windows.net",
	".azurecr.io",
	".azconfig.io",
	".cloudapp.azure.com",
	".azurewebsites.net",
	".azure-api.net",
}

// ClassifyTarget recognizes whether a hostname is an IP literal, a recognized Azure service, a possible Azure service, or an unrecognized target.
func ClassifyTarget(hostname string) (TargetType, AzureServiceFamily) {
	cleanHost := strings.ToLower(strings.TrimSuffix(hostname, "."))

	// Check if IP literal
	if _, err := netip.ParseAddr(cleanHost); err == nil {
		return TargetTypeIPLiteral, FamilyNone
	}

	// Check recognized patterns with boundary safety
	for _, p := range recognizedPatterns {
		if strings.HasSuffix(cleanHost, p.suffix) {
			prefix := strings.TrimSuffix(cleanHost, p.suffix)
			if len(prefix) > 0 && !strings.Contains(prefix, "/") {
				return TargetTypeRecognizedAzure, p.family
			}
		}
	}

	// Check possible Azure generic domains
	for _, domain := range possibleAzureDomains {
		if strings.HasSuffix(cleanHost, domain) {
			prefix := strings.TrimSuffix(cleanHost, domain)
			if len(prefix) > 0 {
				return TargetTypePossibleAzure, FamilyOtherAzure
			}
		}
	}

	return TargetTypeUnrecognized, FamilyNone
}
