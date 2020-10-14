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