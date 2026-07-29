# Private/Catalogue.ps1
# Azure target recognition rules and boundary-safe suffix catalogue for AZPE PowerShell Client

Set-StrictMode -Version Latest

function Get-AzpeServiceCatalogue {
    [CmdletBinding()]
    param ()

    $patterns = @(
        [PSCustomObject]@{ Suffix = ".vault.azure.net"; Family = "KEY_VAULT"; DisplayName = "Key Vault" }
        [PSCustomObject]@{ Suffix = ".managedhsm.azure.net"; Family = "KEY_VAULT"; DisplayName = "Key Vault" }
        [PSCustomObject]@{ Suffix = ".blob.core.windows.net"; Family = "STORAGE_BLOB"; DisplayName = "Storage (Blob)" }
        [PSCustomObject]@{ Suffix = ".dfs.core.windows.net"; Family = "STORAGE_DFS"; DisplayName = "Storage (Data Lake Gen2 / DFS)" }
        [PSCustomObject]@{ Suffix = ".file.core.windows.net"; Family = "STORAGE_FILE"; DisplayName = "Storage (File)" }
        [PSCustomObject]@{ Suffix = ".queue.core.windows.net"; Family = "STORAGE_QUEUE"; DisplayName = "Storage (Queue)" }
        [PSCustomObject]@{ Suffix = ".table.core.windows.net"; Family = "STORAGE_TABLE"; DisplayName = "Storage (Table)" }
        [PSCustomObject]@{ Suffix = ".web.core.windows.net"; Family = "STORAGE_WEB"; DisplayName = "Storage (Static Web)" }
        [PSCustomObject]@{ Suffix = ".search.windows.net"; Family = "AI_SEARCH"; DisplayName = "Azure AI Search" }
        [PSCustomObject]@{ Suffix = ".database.windows.net"; Family = "SQL"; DisplayName = "Azure SQL Database" }
        [PSCustomObject]@{ Suffix = ".documents.azure.com"; Family = "COSMOS_DB"; DisplayName = "Azure Cosmos DB" }
        [PSCustomObject]@{ Suffix = ".mongo.cosmos.azure.com"; Family = "COSMOS_DB"; DisplayName = "Azure Cosmos DB" }
        [PSCustomObject]@{ Suffix = ".cassandra.cosmos.azure.com"; Family = "COSMOS_DB"; DisplayName = "Azure Cosmos DB" }
        [PSCustomObject]@{ Suffix = ".gremlin.cosmos.azure.com"; Family = "COSMOS_DB"; DisplayName = "Azure Cosmos DB" }
        [PSCustomObject]@{ Suffix = ".table.cosmos.azure.com"; Family = "COSMOS_DB"; DisplayName = "Azure Cosmos DB" }
        [PSCustomObject]@{ Suffix = ".openai.azure.com"; Family = "AZURE_OPENAI"; DisplayName = "Azure OpenAI" }
        [PSCustomObject]@{ Suffix = ".azurecr.io"; Family = "CONTAINER_REGISTRY"; DisplayName = "Azure Container Registry" }
        [PSCustomObject]@{ Suffix = ".azconfig.io"; Family = "APP_CONFIGURATION"; DisplayName = "Azure App Configuration" }
        [PSCustomObject]@{ Suffix = ".servicebus.windows.net"; Family = "SERVICE_BUS"; DisplayName = "Azure Service Bus / Event Hubs" }
        [PSCustomObject]@{ Suffix = ".redis.cache.windows.net"; Family = "REDIS_CACHE"; DisplayName = "Azure Cache for Redis" }
        [PSCustomObject]@{ Suffix = ".eventgrid.azure.net"; Family = "EVENT_GRID"; DisplayName = "Azure Event Grid" }
        [PSCustomObject]@{ Suffix = ".service.signalr.net"; Family = "SIGNALR"; DisplayName = "Azure SignalR Service" }
        [PSCustomObject]@{ Suffix = ".datafactory.azure.net"; Family = "DATA_FACTORY"; DisplayName = "Azure Data Factory" }
        [PSCustomObject]@{ Suffix = ".dev.azuresynapse.net"; Family = "SYNAPSE"; DisplayName = "Azure Synapse Analytics" }
        [PSCustomObject]@{ Suffix = ".sql.azuresynapse.net"; Family = "SYNAPSE"; DisplayName = "Azure Synapse SQL" }
        [PSCustomObject]@{ Suffix = ".azure-automation.net"; Family = "AUTOMATION"; DisplayName = "Azure Automation" }
    )

    $possibleDomains = @(
        ".azure.com",
        ".azure.net",
        ".windows.net",
        ".azurecr.io",
        ".azconfig.io",
        ".cloudapp.azure.com",
        ".azurewebsites.net",
        ".azure-api.net",
        ".azmk8s.io"
    )

    return [PSCustomObject]@{
        RecognizedPatterns   = $patterns
        PossibleAzureDomains = $possibleDomains
    }
}

function Get-AzpeFamilyDisplayName {
    [CmdletBinding()]
    param (
        [string]$Family
    )

    switch ($Family) {
        "KEY_VAULT"          { return "Key Vault" }
        "STORAGE_BLOB"       { return "Storage (Blob)" }
        "STORAGE_DFS"        { return "Storage (Data Lake Gen2 / DFS)" }
        "STORAGE_FILE"       { return "Storage (File)" }
        "STORAGE_QUEUE"      { return "Storage (Queue)" }
        "STORAGE_TABLE"      { return "Storage (Table)" }
        "STORAGE_WEB"        { return "Storage (Static Web)" }
        "AI_SEARCH"          { return "Azure AI Search" }
        "SQL"                { return "Azure SQL Database" }
        "COSMOS_DB"          { return "Azure Cosmos DB" }
        "AZURE_OPENAI"       { return "Azure OpenAI" }
        "CONTAINER_REGISTRY" { return "Azure Container Registry" }
        "APP_CONFIGURATION"  { return "Azure App Configuration" }
        "SERVICE_BUS"        { return "Azure Service Bus / Event Hubs" }
        "REDIS_CACHE"        { return "Azure Cache for Redis" }
        "EVENT_GRID"         { return "Azure Event Grid" }
        "SIGNALR"            { return "Azure SignalR Service" }
        "DATA_FACTORY"       { return "Azure Data Factory" }
        "SYNAPSE"            { return "Azure Synapse Analytics" }
        "AUTOMATION"         { return "Azure Automation" }
        "OTHER_AZURE"        { return "Azure Service" }
        default              { return "Unknown Service" }
    }
}

function Classify-AzpeTarget {
    [CmdletBinding()]
    param (
        [string]$Hostname
    )

    $cleanHost = $Hostname.ToLower().TrimEnd('.')

    # Check if host is an IP literal
    [System.Net.IPAddress]$parsedIp = $null
    if ([System.Net.IPAddress]::TryParse($cleanHost, [ref]$parsedIp)) {
        return [PSCustomObject]@{
            TargetType         = "IP_LITERAL"
            AzureServiceFamily = "NONE"
        }
    }

    $cat = Get-AzpeServiceCatalogue

    # Boundary-safe recognized pattern check
    foreach ($p in $cat.RecognizedPatterns) {
        if ($cleanHost.EndsWith($p.Suffix)) {
            $prefix = $cleanHost.Substring(0, $cleanHost.Length - $p.Suffix.Length)
            if ($prefix.Length -gt 0 -and -not $prefix.Contains('/')) {
                return [PSCustomObject]@{
                    TargetType         = "RECOGNIZED_AZURE_SERVICE"
                    AzureServiceFamily = $p.Family
                }
            }
        }
    }

    # Possible Azure generic domain check
    foreach ($domain in $cat.PossibleAzureDomains) {
        if ($cleanHost.EndsWith($domain)) {
            $prefix = $cleanHost.Substring(0, $cleanHost.Length - $domain.Length)
            if ($prefix.Length -gt 0) {
                return [PSCustomObject]@{
                    TargetType         = "POSSIBLE_AZURE_SERVICE"
                    AzureServiceFamily = "OTHER_AZURE"
                }
            }
        }
    }

    return [PSCustomObject]@{
        TargetType         = "UNRECOGNIZED_TARGET"
        AzureServiceFamily = "NONE"
    }
}
