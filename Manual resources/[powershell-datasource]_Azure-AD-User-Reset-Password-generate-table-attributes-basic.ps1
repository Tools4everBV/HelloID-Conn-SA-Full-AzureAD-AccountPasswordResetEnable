# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $id = $datasource.selectedUser.Id

    Write-Verbose "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;
         
    Write-Information "Searching for AzureAD user Id=$id"

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $properties = @("id","displayName","userPrincipalName","givenName","surname","department","jobTitle","companyName","businessPhones","mobilePhone")
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$id" + '?$select=' + ($properties -join ",")
    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false

    foreach($tmp in $azureADUser.psObject.properties)
    {
        if($tmp.Name -in $properties){
            $returnObject = @{
                name=$tmp.Name;
                value=$tmp.value
            }
            Write-Output $returnObject
        }
    }
   
    Write-Information "Finished retrieving AzureAD user [$id] basic attributes"
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD user [$id]. Error: $_" + $errorDetailsMessage)
}
