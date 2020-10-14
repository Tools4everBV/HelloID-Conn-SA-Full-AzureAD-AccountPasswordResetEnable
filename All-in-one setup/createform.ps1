#HelloID variables
$PortalBaseUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users", "HID_administrators")
 
# Create authorization headers with HelloID API key
$pair = "$apiKey" + ":" + "$apiSecret"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$key = "Basic $base64"
$headers = @{"authorization" = $Key}
# Define specific endpoint URI
if($PortalBaseUrl.EndsWith("/") -eq $false){
    $PortalBaseUrl = $PortalBaseUrl + "/"
}
 
function Write-ColorOutput($ForegroundColor) {
  $fc = $host.UI.RawUI.ForegroundColor
  $host.UI.RawUI.ForegroundColor = $ForegroundColor
  
  if ($args) {
      Write-Output $args
  }
  else {
      $input | Write-Output
  }

  $host.UI.RawUI.ForegroundColor = $fc
}

$variableName = "AADtenantID"
$variableGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automation/variables/named/$variableName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.automationVariableGuid)) {
        #Create Variable
        $body = @{
            name = "$variableName";
            value = '<Provide your Tenant ID here>';
            secret = "false";
            ItemType = 0;
        }
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automation/variable")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $variableGuid = $response.automationVariableGuid

        Write-ColorOutput Green "Variable '$variableName' created: $variableGuid"
    } else {
        $variableGuid = $response.automationVariableGuid
        Write-ColorOutput Yellow "Variable '$variableName' already exists: $variableGuid"
    }
} catch {
    Write-ColorOutput Red "Variable '$variableName'"
    $_
}

$variableName = "AADAppId"
$variableGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automation/variables/named/$variableName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.automationVariableGuid)) {
        #Create Variable
        $body = @{
            name = "$variableName";
            value = '<Provide your Client ID here>';
            secret = "false";
            ItemType = 0;
        }
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automation/variable")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $variableGuid = $response.automationVariableGuid

        Write-ColorOutput Green "Variable '$variableName' created: $variableGuid"
    } else {
        $variableGuid = $response.automationVariableGuid
        Write-ColorOutput Yellow "Variable '$variableName' already exists: $variableGuid"
    }
} catch {
    Write-ColorOutput Red "Variable '$variableName'"
    $_
}

$variableName = "AADAppSecret"
$variableGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automation/variables/named/$variableName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.automationVariableGuid)) {
        #Create Variable
        $body = @{
            name = "$variableName";
            value = '<Provide your Client Secret here>';
            secret = "true";
            ItemType = 0;
        }
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automation/variable")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $variableGuid = $response.automationVariableGuid

        Write-ColorOutput Green "Variable '$variableName' created: $variableGuid"
    } else {
        $variableGuid = $response.automationVariableGuid
        Write-ColorOutput Yellow "Variable '$variableName' already exists: $variableGuid"
    }
} catch {
    Write-ColorOutput Red "Variable '$variableName'"
    $_
}

  
$taskName = "AzureAD-user-generate-table-wildcard"
$taskGetUsersGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automationtasks?search=$taskName&container=1")
    $response = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false) | Where-Object -filter {$_.name -eq $taskName}
  
    if([string]::IsNullOrEmpty($response.automationTaskGuid)) {
        #Create Task
  
        $body = @{
            name = "$taskName";
            useTemplate = "false";
            powerShellScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $searchValue = $formInput.searchUser
    $searchQuery = "*$searchValue*"
      
      
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        Hid-Add-TaskResult -ResultValue []
    }else{
        HID-Write-Summary -Message "Searching for: $searchQuery" -Event Information
          
        Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information

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

        Hid-Write-Status -Message "Searching for: $searchQuery" -Event Information
        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }
 
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/users" + '?$select=UserPrincipalName,displayName,department,jobTitle,companyName' + '&$top=999'
 
        $azureADUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADUsers = $azureADUsersResponse.value
        while (![string]::IsNullOrEmpty($azureADUsersResponse.'@odata.nextLink')) {
            $azureADUsersResponse = Invoke-RestMethod -Uri $azureADUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
            $azureADUsers += $azureADUsersResponse.value
        }  

        $users = foreach($azureADUser in $azureADUsers){
            if($azureADUser.displayName -like $searchQuery -or $azureADUser.userPrincipalName -like $searchQuery){
                $azureADUser
            }
        }

        $users = $users | Sort-Object -Property DisplayName
        $resultCount = @($users).Count
        Hid-Write-Status -Message "Result count: $resultCount" -Event Information
        HID-Write-Summary -Message "Result count: $resultCount" -Event Information
          
        if($resultCount -gt 0){
            foreach($user in $users){
                $returnObject = @{UserPrincipalName=$user.UserPrincipalName; displayName=$user.displayName; department=$user.department; Title=$user.jobTitle; Company=$user.companyName}
                Hid-Add-TaskResult -ResultValue $returnObject
            }
        } else {
            Hid-Add-TaskResult -ResultValue []
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    HID-Write-Status -Message ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage) -Event Error
    HID-Write-Summary -Message "Error searching for AzureAD groups" -Event Failed
     
    Hid-Add-TaskResult -ResultValue []
}
  
'@;
            automationContainer = "1";
            variables = @()
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskGetUsersGuid = $response.automationTaskGuid

        Write-ColorOutput Green "Powershell task '$taskName' created: $taskGetUsersGuid"    
    } else {
        #Get TaskGUID
        $taskGetUsersGuid = $response.automationTaskGuid
        Write-ColorOutput Yellow "Powershell task '$taskName' already exists: $taskGetUsersGuid"
    }
} catch {
    Write-ColorOutput Red "Powershell task '$taskName'"
    $_
}  
  
  
$dataSourceName = "AzureAD-user-generate-table-wildcard"
$dataSourceGetUsersGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "3";
            model = @(@{key = "Company"; type = 0}, @{key = "Department"; type = 0}, @{key = "Description"; type = 0}, @{key = "displayName"; type = 0}, @{key = "SamAccountName"; type = 0}, @{key = "Title"; type = 0}, @{key = "UserPrincipalName"; type = 0});
            automationTaskGUID = "$taskGetUsersGuid";
            input = @(@{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "searchUser"; type = "0"; options = "1"})
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
          
        $dataSourceGetUsersGuid = $response.dataSourceGUID
        Write-ColorOutput Green "Task data source '$dataSourceName' created: $dataSourceGetUsersGuid"
    } else {
        #Get DatasourceGUID
        $dataSourceGetUsersGuid = $response.dataSourceGUID
        Write-ColorOutput Yellow "Task data source '$dataSourceName' already exists: $dataSourceGetUsersGuid"
    }
} catch {
  Write-ColorOutput Red "Task data source '$dataSourceName'"
  $_
}
  
  
  
$taskName = "AzureAD-user-generate-table-attributes-basic"
$taskGetUserDetailsGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automationtasks?search=$taskName&container=1")
    $response = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false) | Where-Object -filter {$_.name -eq $taskName}
  
    if([string]::IsNullOrEmpty($response.automationTaskGuid)) {
        #Create Task
  
        $body = @{
            name = "$taskName";
            useTemplate = "false";
            powerShellScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $userPrincipalName = $formInput.selectedUser.UserPrincipalName

    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information

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
         
    Hid-Write-Status -Message "Searching for AzureAD user userPrincipalName=$userPrincipalName" -Event Information


    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $properties = @("displayName","userPrincipalName","givenName","surname","department","jobTitle","companyName","businessPhones","mobilePhone")
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName" + '?$select=' + ($properties -join ",")
    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    HID-Write-Status -Message "Finished searching AzureAD user [$userPrincipalName]" -Event Information
      
    foreach($tmp in $azureADUser.psObject.properties)
    {
        if($tmp.Name -in $properties){
            $returnObject = @{name=$tmp.Name; value=$tmp.value}
            Hid-Add-TaskResult -ResultValue $returnObject
        }
    }
   
    HID-Write-Status -Message "Finished retrieving AzureAD user [$userPrincipalName] basic attributes" -Event Success
    HID-Write-Summary -Message "Finished retrieving AzureAD user [$userPrincipalName] basic attributes" -Event Success
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    HID-Write-Status -Message ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage) -Event Error
    HID-Write-Summary -Message "Error searching for AzureAD groups" -Event Failed
     
    Hid-Add-TaskResult -ResultValue []
}
'@;
            automationContainer = "1";
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskGetUserDetailsGuid = $response.automationTaskGuid

        Write-ColorOutput Green "Powershell task '$taskName' created: $taskGetUserDetailsGuid"  
    } else {
        #Get TaskGUID
        $taskGetUserDetailsGuid = $response.automationTaskGuid
        Write-ColorOutput Yellow "Powershell task '$taskName' already exists: $taskGetUserDetailsGuid"
    }
} catch {
    Write-ColorOutput Red "Powershell task '$taskName'"
    $_
}  
  
  
$dataSourceName = "AzureAD-user-generate-table-attributes-basic"
$dataSourceGetUserDetailsGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "3";
            model = @(@{key = "name"; type = 0}, @{key = "value"; type = 0});
            automationTaskGUID = "$taskGetUserDetailsGuid";
            input = @(@{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "selectedUser"; type = "0"; options = "1"})
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
          
        $dataSourceGetUserDetailsGuid = $response.dataSourceGUID
        Write-ColorOutput Green "Task data source '$dataSourceName' created: $dataSourceGetUserDetailsGuid"
    } else {
        #Get DatasourceGUID
        $dataSourceGetUserDetailsGuid = $response.dataSourceGUID
        Write-ColorOutput Yellow "Task data source '$dataSourceName' already exists: $dataSourceGetUserDetailsGuid"
    }
} catch {
    Write-ColorOutput Red "Task data source '$dataSourceName'"
    $_
}
  
  
  
$formName = "AzureAD Account - Reset password & Enable"
$formGuid = ""
  
try
{
    try {
        $uri = ($PortalBaseUrl +"api/v1/forms/$formName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    } catch {
        $response = $null
    }
  
    if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true))
    {
        #Create Dynamic form
        $form = @"
[
  {
    "label": "Select user account",
    "fields": [
      {
        "key": "searchfield",
        "templateOptions": {
          "label": "Search",
          "placeholder": "Username or email address"
        },
        "type": "input",
        "summaryVisibility": "Hide element",
        "requiresTemplateOptions": true
      },
      {
        "key": "gridUsers",
        "templateOptions": {
          "label": "Select user",
          "required": true,
          "grid": {
            "columns": [
              {
                "headerName": "Display Name",
                "field": "displayName"
              },
              {
                "headerName": "Description",
                "field": "Description"
              },
              {
                "headerName": "User Principal Name",
                "field": "UserPrincipalName"
              },
              {
                "headerName": "Sam Account Name",
                "field": "SamAccountName"
              },
              {
                "headerName": "Company",
                "field": "Company"
              },
              {
                "headerName": "Department",
                "field": "Department"
              },
              {
                "headerName": "Title",
                "field": "Title"
              }
            ],
            "height": 300,
            "rowSelection": "single"
          },
          "dataSourceConfig": {
            "dataSourceGuid": "$dataSourceGetUsersGuid",
            "input": {
              "propertyInputs": [
                {
                  "propertyName": "searchUser",
                  "otherFieldValue": {
                    "otherFieldKey": "searchfield"
                  }
                }
              ]
            }
          }
        },
        "type": "grid",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      }
    ]
  },
  {
    "label": "Reset password",
    "fields": [
      {
        "key": "gridDetails",
        "templateOptions": {
          "label": "Basic attributes",
          "required": false,
          "grid": {
            "columns": [
              {
                "headerName": "Name",
                "field": "name"
              },
              {
                "headerName": "Value",
                "field": "value"
              }
            ],
            "height": 350,
            "rowSelection": "single"
          },
          "dataSourceConfig": {
            "dataSourceGuid": "$dataSourceGetUserDetailsGuid",
            "input": {
              "propertyInputs": [
                {
                  "propertyName": "selectedUser",
                  "otherFieldValue": {
                    "otherFieldKey": "gridUsers"
                  }
                }
              ]
            }
          },
          "useFilter": false
        },
        "type": "grid",
        "summaryVisibility": "Hide element",
        "requiresTemplateOptions": true
      },
      {
        "key": "blnreset",
        "templateOptions": {
          "label": "Reset password",
          "useSwitch": true,
          "checkboxLabel": " "
        },
        "type": "boolean",
        "defaultValue": true,
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "password",
        "templateOptions": {
          "label": "New password"
        },
        "hideExpression": "!model[\\"blnreset\\"]",
        "type": "passwordconfirm",
        "summaryVisibility": "Hide value",
        "requiresTemplateOptions": true
      },
      {
        "key": "blnchangenextsignin",
        "templateOptions": {
          "label": "Change password at next sign in",
          "useSwitch": true,
          "checkboxLabel": ""
        },
        "hideExpression": "!model[\\"blnreset\\"]",
        "type": "boolean",
        "defaultValue": true,
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "blnenable",
        "templateOptions": {
          "label": "Enable account",
          "useSwitch": true,
          "checkboxLabel": ""
        },
        "type": "boolean",
        "defaultValue": true,
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      }
    ]
  }
]
"@
  
        $body = @{
            Name = "$formName";
            FormSchema = $form
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/forms")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
  
        $formGuid = $response.dynamicFormGUID
        Write-ColorOutput Green "Dynamic form '$formName' created: $formGuid"
    } else {
        $formGuid = $response.dynamicFormGUID
        Write-ColorOutput Yellow "Dynamic form '$formName' already exists: $formGuid"
    }
} catch {
    Write-ColorOutput Red "Dynamic form '$formName'"
    $_
}
  
  
  
$delegatedFormAccessGroupGuids = @()

foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-ColorOutput Green "HelloID (access)group '$group' successfully found: $delegatedFormAccessGroupGuid"
    } catch {
        Write-ColorOutput Red "HelloID (access)group '$group'"
        $_
    }
}
  
  
  
$delegatedFormName = "AzureAD Account - Reset password & Unlock"
$delegatedFormGuid = ""
$delegatedFormCreated = $false
  
try {
    try {
        $uri = ($PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    } catch {
        $response = $null
    }
  
    if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
        #Create DelegatedForm
        $body = @{
            name = "$delegatedFormName";
            dynamicFormGUID = "$formGuid";
            isEnabled = "True";
            accessGroups = $delegatedFormAccessGroupGuids;
            useFaIcon = "True";
            faIcon = "fa fa-key";
        }  
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/delegatedforms")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
  
        $delegatedFormGuid = $response.delegatedFormGUID
        Write-ColorOutput Green "Delegated form '$delegatedFormName' created: $delegatedFormGuid"
        $delegatedFormCreated = $true
    } else {
        #Get delegatedFormGUID
        $delegatedFormGuid = $response.delegatedFormGUID
        Write-ColorOutput Yellow "Delegated form '$delegatedFormName' already exists: $delegatedFormGuid"
    }
} catch {
    Write-ColorOutput Red "Delegated form '$delegatedFormName'"
    $_
}
  
  
  
  
$taskActionName = "AzureAD-user-reset-enable"
$taskActionGuid = ""
  
try {
    if($delegatedFormCreated -eq $true) {
        #Create Task
  
        $body = @{
            name = "$taskActionName";
            useTemplate = "false";
            powerShellScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#Change mapping here
if($blnreset -eq 'true' -and $blnenable -eq 'true'){
    $account = [PSCustomObject]@{
        userPrincipalName = $userPrincipalName;
        accountEnabled = $true;
        passwordProfile = @{
            password = $password
            forceChangePasswordNextSignIn = [System.Convert]::ToBoolean($blnchangenextsignin)
        }
    }
}elseif($blnreset -eq 'false' -and $blnenable -eq 'true'){
    $account = [PSCustomObject]@{
        userPrincipalName = $userPrincipalName;
        accountEnabled = $true;
    }
}

try{
    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information

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

    Hid-Write-Status -Message "Updating AzureAD user [$($account.userPrincipalName)].." -Event Information
 
    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $baseUpdateUri = "https://graph.microsoft.com/"
    $updateUri = $baseUpdateUri + "v1.0/users/$($account.userPrincipalName)"
    $body = $account | ConvertTo-Json -Depth 10
 
    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

    Hid-Write-Status -Message "AzureAD user [$($account.userPrincipalName)] updated successfully" -Event Success
    HID-Write-Summary -Message "AzureAD user [$($account.userPrincipalName)] updated successfully" -Event Success
}catch{
    if(-Not($_.Exception.Response -eq $null)){
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $errResponse = $reader.ReadToEnd();

        HID-Write-Status -Message "Error updating AzureAD user [$($account.userPrincipalName)]. Error: $errResponse" -Event Error
        HID-Write-Summary -Message "Error updating AzureAD user [$($account.userPrincipalName)]" -Event Failed
    }else{
        HID-Write-Status -Message "Error updating AzureAD user [$($account.userPrincipalName)]. Error: $($_.Exception.Message)" -Event Error
        HID-Write-Summary -Message "Error updating AzureAD user [$($account.userPrincipalName)]" -Event Failed
    }
}
'@;
            automationContainer = "8";
            objectGuid = "$delegatedFormGuid";
            variables = @(@{name = "blnchangenextsignin"; value = "{{form.blnchangenextsignin}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "blnenable"; value = "{{form.blnenable}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "blnreset"; value = "{{form.blnreset}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "password"; value = "{{form.password}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "userPrincipalName"; value = "{{form.gridUsers.UserPrincipalName}}"; typeConstraint = "string"; secret = "False"});
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskActionGuid = $response.automationTaskGuid

        Write-ColorOutput Green "Delegated form task '$taskActionName' created: $taskActionGuid"  
    } else {
        Write-ColorOutput Yellow "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..."
    }
} catch {
    Write-ColorOutput Red "Delegated form task '$taskActionName'"
    $_
}