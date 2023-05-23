#Windows 11 Group Tag Converter Function App

<#
.SYNOPSIS
Windows 11 Group Tag Converter Function App
This is the Function App which receives client requests and processes confirmation or alteration of the client devices group tag

.Description
1. Receive a request and pull out the information
2. Confirm the requesting device identity using MSEndpointMGRs latest auth methods for HTTP functions: https://github.com/MSEndpointMgr/AADDeviceTrust
3. Check the group tag of that current SN
4. If already correct, reply as such
5. Otherwise, change the tag and let the device know.

.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2023-03-26
Updated:     2023-05-21
            
Version history:

1 - 2023-03-26 - Creation
2 - 2023-05-07 - Updated to latest MSEndpointMGR authentication methods. Credit to NickolajA
3 - 2023-05-21 - Updated to latest authentication methods improved by @AzureToTheMax. Not sure when they will be rolled into the main line.

#>



using namespace System.Net
# Input bindings are passed in via param block.

param($Request)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


#region functions
function Get-SelfGraphAuthToken {
    <#
    .SYNOPSIS
        Use the permissions granted to the Function App itself to obtain a Graph token for running Graph queries. 
        Returns a formated header for use with the original code.
    
    .NOTES
        Author:      Maxton Allen
        Contact:     @AzureToTheMax
        Created:     2021-06-07
        Updated:     2023-02-17
        Original: Nickolaj Andersen, @NickolajA

    
        Version history:
        1 - 2021-06-07 Function created
        2 - 2023-02-17 Updated to API Version 2019-08-01 from 2017-09-01
    #>
    Process {

        $resourceURI = "https://graph.microsoft.com"
        $tokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
        $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $tokenAuthURI

        
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($tokenResponse.access_token)"
            "ExpiresOn" = $tokenResponse.expires_on
        }
        return $AuthenticationHeader
    }
}#end function 



Function Get-AppRegGraphToken { 
<#
.SYNOPSIS
    Use the permissions granted to the App Registration to obtain a Graph token for making Graph queries. 
    Returns a formatted header.

.NOTES
    Author:      Maxton Allen
    Contact:     @AzureToTheMax
    Created:     2023-02-17
    Updated:     2023-05-07

    Version history:
    1 (2023-02-17) Function created
    2 (2023-05-07) Reformated to return a full header rather than just the bearer token as new process no longer requires both.
#>

    [cmdletbinding()] 
    Param( 
        [parameter(Mandatory = $true)] 
        [pscredential]$Credential, 
        [parameter(Mandatory = $true)] 
        [string]$tenantID 
    ) 

    
    #Get token 
    $AuthUri = "https://login.microsoftonline.com/$TenantID/oauth2/token" 
    $Resource = 'graph.microsoft.com' 
    $AuthBody = "grant_type=client_credentials&client_id=$($credential.UserName)&client_secret=$($credential.GetNetworkCredential().Password)&resource=https%3A%2F%2F$Resource%2F" 
    $Response = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $AuthBody 
    If ($Response.access_token) { 
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($Response.access_token)"
            "ExpiresOn" = $Response.expires_on
        }
        return $AuthenticationHeader
    } 
    Else { 
        Throw "Authentication failed" 
    } 
} #End function

function Get-AzureADDeviceAlternativeSecurityIds {
    <#
    .SYNOPSIS
        Decodes Key property of an Azure AD device record into prefix, thumbprint and publickeyhash values.
    
    .DESCRIPTION
        Decodes Key property of an Azure AD device record into prefix, thumbprint and publickeyhash values.

    .PARAMETER Key
        Specify the 'key' property of the alternativeSecurityIds property retrieved from the Get-AzureADDeviceRecord function.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the 'key' property of the alternativeSecurityIds property retrieved from the Get-AzureADDeviceRecord function.")]
        [ValidateNotNullOrEmpty()]
        [string]$Key
    )
    Process {
        $DecodedKey = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Key))
        $PSObject = [PSCustomObject]@{
            "Prefix" = $DecodedKey.SubString(0,21)
            "Thumbprint" = $DecodedKey.Split(">")[1].SubString(0,40)
            "PublicKeyHash" = $DecodedKey.Split(">")[1].SubString(40)
        }

        # Handle return response
        return $PSObject
    }
}

function Get-AzureADDeviceRecord {
    <#
    .SYNOPSIS
        Retrieve an Azure AD device record.
    
    .DESCRIPTION
        Retrieve an Azure AD device record.

    .PARAMETER DeviceID
        Specify the Device ID of an Azure AD device record.

    .PARAMETER AuthToken
        Specify a hash table consisting of the authentication headers.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2022-01-01
    
        Version history:
        1.0.0 - (2021-06-07) Function created
        1.0.1 - (2022-01-01) Added support for passing in the authentication header table to the function
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Device ID of an Azure AD device record.")]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceID,

        [parameter(Mandatory = $true, HelpMessage = "Specify a hash table consisting of the authentication headers.")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$AuthToken
    )
    Process {
        $GraphURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($DeviceID)'"
        $GraphResponse = (Invoke-RestMethod -Method "Get" -Uri $GraphURI -ContentType "application/json" -Headers $AuthToken -ErrorAction Stop).value
        
        # Handle return response
        return $GraphResponse
    }
}

function Test-AzureADDeviceAlternativeSecurityIds {
    <#
    .SYNOPSIS
        Validate the thumbprint and publickeyhash property values of the alternativeSecurityIds property from the Azure AD device record.
    
    .DESCRIPTION
        Validate the thumbprint and publickeyhash property values of the alternativeSecurityIds property from the Azure AD device record.

    .PARAMETER AlternativeSecurityIdKey
        Specify the alternativeSecurityIds.Key property from an Azure AD device record.

    .PARAMETER Type
        Specify the type of the AlternativeSecurityIdsKey object, e.g. Thumbprint or Hash.

    .PARAMETER Value
        Specify the value of the type to be validated.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2023-05-10
    
        Version history:
        1.0.0 - (2021-06-07) Function created
        1.0.1 - (2023-02-10) @AzureToTheMax
            1. Updated Thumbprint compare to use actual PEM cert via X502 class rather than simply a passed and seperate thumbprint value.
            2. Updated Hash compare to use full PEM cert via the X502 class, pull out just the public key data, and compare from that like before.

    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the alternativeSecurityIds.Key property from an Azure AD device record.")]
        [ValidateNotNullOrEmpty()]
        [string]$AlternativeSecurityIdKey,

        [parameter(Mandatory = $true, HelpMessage = "Specify the type of the AlternativeSecurityIdsKey object, e.g. Thumbprint or Hash.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Thumbprint", "Hash")]
        [string]$Type,

        [parameter(Mandatory = $true, HelpMessage = "Specify the value of the type to be validated.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    Process {
        # Construct custom object for alternativeSecurityIds property from Azure AD device record, used as reference value when compared to input value
        $AzureADDeviceAlternativeSecurityIds = Get-AzureADDeviceAlternativeSecurityIds -Key $AlternativeSecurityIdKey
        
        switch ($Type) {
            "Thumbprint" {
                Write-Output "Using new X502 Thumbprint compare"

                # Convert Value (cert) passed back to X502 Object
                $X502 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([System.Convert]::FromBase64String($Value))

                # Validate match
                if ($X502.thumbprint -match $AzureADDeviceAlternativeSecurityIds.Thumbprint) {
                    return $true
                }
                else {
                    return $false
                }
            }
            "Hash" {
                Write-Output "Using new X502 hash compare"

                # Convert Value (cert) passed back to X502 Object
                $X502 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([System.Convert]::FromBase64String($Value))

                # Pull out just the public key, removing extended values
                $X502Pub = [System.Convert]::ToBase64String($X502.PublicKey.EncodedKeyValue.rawData)
        
                # Convert from Base64 string to byte array
                $DecodedBytes = [System.Convert]::FromBase64String($X502Pub)
                
                # Construct a new SHA256Managed object to be used when computing the hash
                $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

                # Compute the hash
                [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($DecodedBytes)

                # Convert computed hash to Base64 string
                $ComputedHashString = [System.Convert]::ToBase64String($ComputedHash)

                # Validate match
                if ($ComputedHashString -like $AzureADDeviceAlternativeSecurityIds.PublicKeyHash) {
                    return $true
                }
                else {
                    return $false
                }
            }
        }
    }
}


function Test-Encryption {
    <#
    .SYNOPSIS
        Test the signature created with the private key by using the public key.
    
    .DESCRIPTION
        Test the signature created with the private key by using the public key.

    .PARAMETER PublicKeyEncoded
        Specify the Base64 encoded string representation of the Public Key.

    .PARAMETER Signature
        Specify the Base64 encoded string representation of the signature coming from the inbound request.

    .PARAMETER Content
        Specify the content string that the signature coming from the inbound request is based upon.
    
    .NOTES
        Author:      Nickolaj Andersen / Thomas Kurth
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2023-05-10
    
        Version history:
        1.0.0 - (2021-06-07) Function created
        1.0.1 - (2023-05-10) @AzureToTheMax - Updated to use full PEM cert via X502, extract the public key, and perform test like before using that.

        Credits to Thomas Kurth for sharing his original C# code.
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Base64 encoded string representation of the Public Key.")]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKeyEncoded,

        [parameter(Mandatory = $true, HelpMessage = "Specify the Base64 encoded string representation of the signature coming from the inbound request.")]
        [ValidateNotNullOrEmpty()]
        [string]$Signature,

        [parameter(Mandatory = $true, HelpMessage = "Specify the content string that the signature coming from the inbound request is based upon.")]
        [ValidateNotNullOrEmpty()]
        [string]$Content
    )
    Process {

        Write-Output "Using new X502 encryption test"
        # Convert Value (cert) passed back to X502 Object
        $X502 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([System.Convert]::FromBase64String($PublicKeyEncoded))

        # Pull out just the public key, removing extended values
        $X502Pub = [System.Convert]::ToBase64String($X502.PublicKey.EncodedKeyValue.rawData)

        # Convert encoded public key from Base64 string to byte array
        $PublicKeyBytes = [System.Convert]::FromBase64String($X502Pub)

        # Convert signature from Base64 string
        [byte[]]$Signature = [System.Convert]::FromBase64String($Signature)

        # Extract the modulus and exponent based on public key data
        $ExponentData = [System.Byte[]]::CreateInstance([System.Byte], 3)
        $ModulusData = [System.Byte[]]::CreateInstance([System.Byte], 256)
        [System.Array]::Copy($PublicKeyBytes, $PublicKeyBytes.Length - $ExponentData.Length, $ExponentData, 0, $ExponentData.Length)
        [System.Array]::Copy($PublicKeyBytes, 9, $ModulusData, 0, $ModulusData.Length)

        # Construct RSACryptoServiceProvider and import modolus and exponent data as parameters to reconstruct the public key from bytes
        $PublicKey = [System.Security.Cryptography.RSACryptoServiceProvider]::Create(2048)
        $RSAParameters = $PublicKey.ExportParameters($false)
        $RSAParameters.Modulus = $ModulusData
        $RSAParameters.Exponent = $ExponentData
        $PublicKey.ImportParameters($RSAParameters)

        # Construct a new SHA256Managed object to be used when computing the hash
        $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

        # Construct new UTF8 unicode encoding object
        $UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8

        # Convert content to byte array
        [byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)

        # Compute the hash
        [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)

        # Verify the signature with the computed hash of the content using the public key
        $PublicKey.VerifyHash($ComputedHash, $Signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
}

function Get-AzureADDeviceIDFromCertificate {
    <#
   .SYNOPSIS
       Used to pull the Azure Device ID from the provided Base64 certificate.
   
   .DESCRIPTION
       Used by the function app to pull the Azure Device ID from the provided Base64 certificate.
   
   .NOTES
       Author:      Maxton Allen 
       Contact:     @AzureToTheMax
       Created:     2023-05-14
       Updated:     2023-05-14
   
       Version history:
       1.0.0 - (2023-05-14) created
   #>
   param(    
       [parameter(Mandatory = $true, HelpMessage = "Specify a Base64 encoded value for which an Azure Device ID will be extracted.")]
       [ValidateNotNullOrEmpty()]
       [string]$Value
   )
   Process {
       # Convert Value (cert) passed back to X502 Object
       $X502 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([System.Convert]::FromBase64String($Value))

       # Get the Subject (issued to)
       $Subject = $X502.Subject

       # Remove the leading "CN="
       $SubjectTrimed = $Subject.TrimStart("CN=")

       # Handle return
       Return $SubjectTrimed
   }
}


#endregion











<#
.Description
If you had to use an App registration alone, you could swap out all instance of self-auth funciton calls with AppReg function calls and use the below to tell the Function those values.
You would want to use a key vault for the secret.

# Get secrets from Keyvault
$appId = $env:appId #Enterprise App Registrations App ID
$appSecret = $env:appSecret #Your Registered Apps Secret Key Value
#>

#endregion functions
######################################################################




#region local-testing-auth
#This allows you to run/test the funciton app in visual. 
#You need an App Registration with the same permissions as the Function and you need those values in a CSV file on your system.
#CSV is better than directly in code - that way you can push code without redacting keys and secrets.
$RunningComputerName = $env:COMPUTERNAME
$MyComputerName = "YOUR PC" #Your Computer Name
    if ($RunningComputerName -eq $MyComputerName){
          
        #Set Running enviroment variable as Local
        $RunLocation = "Local"

        #The location of your CSV file containing headers and information for the below variables.
        $SecretsCSV = Import-Csv "C:\Path\to\Secrets.csv"

        #See Above Section for explination on values
        $appId = $SecretsCSV.Appid
        $appSecret = $SecretsCSV.AppSecret
        $TenantID = $SecretsCSV.TenantID

        } else {
            #Set our token method to cloud (It's the Function App)
            $RunLocation = "Cloud"
        }

#endregion







#Start Script
Write-Information "Windows 11 Group Tag Converter received a request."

######################################################################
#region Variables

#get auth token for use within script either via cloud or local (app reg)
if($RunLocation -eq "Cloud"){
    #Use Function permissions to get Graph token
    write-host "Running as Cloud: Using Self-Authentication"
    $AuthToken = Get-SelfGraphAuthToken
    #Write-Information "Cloud auth token: $($AuthToken.Authorization)" #Used in troubleshooting
} else {
    #Use app reg for Graph token
    write-host "Running as Local: Using App Registration"
    $Credential = New-Object System.Management.Automation.PSCredential($AppID, (ConvertTo-SecureString $AppSecret -AsPlainText -Force)) 
    $AuthToken = Get-AppRegGraphToken -credential $Credential -TenantID $TenantID 
    #Write-Information "Local auth token: $($AuthToken.Authorization)" #Used in troubleshooting
}

# Initate variables
$StatusCode = [HttpStatusCode]::OK
$Body = [string]::Empty

#Extract variables from payload with information on what needs to happen
$SerialNumber = $Request.Body.SerialNumber #The Serial Number of the device
$DesiredGroupTag = $Request.Body.DesiredGroupTag #The tag to change to
$DeviceName = $Request.Body.DeviceName #From AADDeviceTrust
$Signature = $Request.Body.Signature #From AADDeviceTrust
$PublicKey = $Request.Body.PublicKey #From AADDeviceTrust

#Get Device ID from the cert
$DeviceID = Get-AzureADDeviceIDFromCertificate -Value $PublicKey





#endregion
######################################################################



######################################################################
#region Process


# Write logging output.
Write-Output -InputObject "Initiating request handling for device named as '$($DeviceName)' with identifier: $($DeviceID)"

# Declare response object as Arraylist
$ResponseArray = New-Object -TypeName System.Collections.ArrayList

# Retrieve Azure AD device record based on DeviceID property from incoming request body
$AzureADDeviceRecord = Get-AzureADDeviceRecord -DeviceID $DeviceID -AuthToken $AuthToken

#Write-Output "Azure AD Device Record is $($AzureADDeviceRecord) with id $($AzureADDeviceRecord.id)"

if ($AzureADDeviceRecord -ne $null) {
    Write-Output -InputObject "Found trusted Azure AD device record with object identifier: $($AzureADDeviceRecord.id)"

    # Validate thumbprint from input request with Azure AD device record's alternativeSecurityIds details
    if (Test-AzureADDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $AzureADDeviceRecord.alternativeSecurityIds.key -Type "Thumbprint" -Value $PublicKey) {
        Write-Output -InputObject "Successfully validated certificate thumbprint from inbound request"

        # Validate public key hash from input request with Azure AD device record's alternativeSecurityIds details
        if (Test-AzureADDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $AzureADDeviceRecord.alternativeSecurityIds.key -Type "Hash" -Value $PublicKey) {
            Write-Output -InputObject "Successfully validated certificate SHA256 hash value from inbound request"

            $EncryptionVerification = Test-Encryption -PublicKeyEncoded $PublicKey -Signature $Signature -Content $AzureADDeviceRecord.deviceId
            if ($EncryptionVerification -eq $true) {
                Write-Output -InputObject "Successfully validated inbound request came from a trusted Azure AD device record"

                # Validate that the inbound request came from a trusted device that's not disabled
                if ($AzureADDeviceRecord.accountEnabled -eq $true) {
                    Write-Output -InputObject "Azure AD device record was validated as enabled"


                    ###################################
                    #Start tag checking and conversion#
                    ###################################

                    #Query Graph for current Device Group Tag
                #You need the SN and DeviceManagementServiceConfig.ReadWrite.All permission
                $graphApiVersion = "beta"
                $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
                $encoded = [uri]::EscapeDataString($SerialNumber)
                $AutoPilotInfouri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=contains(serialNumber,'$encoded')"
                $GroupTagResponse = (Invoke-RestMethod -Method "Get" -Uri $AutoPilotInfouri -ContentType "application/json" -Headers $AuthToken -ErrorAction Stop).value
                $CurrentGroupTag = $GroupTagResponse.groupTag
                $DeviceAutopilotID = $GroupTagResponse.ID
               
                #This is a converter from A to B so it should never have a null value
                if ($CurrentGroupTag -ne $null) {
                    if ($CurrentGroupTag -eq $DesiredGroupTag){
                        #already under the right tag
                        Write-Information "$($DeviceName) is already under $($DesiredGroupTag)"
                            $PSObject = [PSCustomObject]@{
                                ComputerName = $DeviceName
                                CurrentGroupTag = $CurrentGroupTag
                                Response = "200: Device is already under requested Group Tag $($DesiredGroupTag)"
                            }    
                        $ResponseArray.Add($PSObject) | Out-Null
                        $StatusCode = [HttpStatusCode]::OK

                        } else {
                        #Request graph to change the tag
                        Write-Information "$($DeviceName) is currently under tag $($CurrentGroupTag). Changing to tag $($DesiredGroupTag)"
                        $graphApiVersion = "beta"
                        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$DeviceAutopilotID/UpdateDeviceProperties"
                        $json = "{"
                        $json = $json + " groupTag: `"$DesiredGroupTag`""
                        $json = $json + " }"
                        $GroupTagResponse = (Invoke-WebRequest -Method "POST" -Uri $uri -ContentType "application/json" -Headers $AuthToken -Body $json -ErrorAction Stop).StatusCode

                        $PSObject = [PSCustomObject]@{
                            ComputerName = $DeviceName
                            DesiredGroupTag = $DesiredGroupTag 
                            PreviousGroupTag = $CurrentGroupTag
                            CurrentGroupTag = $DesiredGroupTag
                            Response = $GroupTagResponse
                            ResponseDescription = "Device changed to $($DesiredGroupTag)"
                        }
                        $ResponseArray.Add($PSObject) | Out-Null
                        $StatusCode = [HttpStatusCode]::OK
                        }



                } else {
                    Write-Warning "CurrentGroupTag was null!"
                    $PSObject = [PSCustomObject]@{
                        ComputerName = $DeviceName
                        Response = "400: CurrentGroupTag for requesting device $($DeviceName) is null!"
                    }    
                    $StatusCode = [HttpStatusCode]::Forbidden
                    $ResponseArray.Add($PSObject) | Out-Null
                }

                    ########################
                    #Resume original script#
                    ########################


                }
                else {
                    Write-Output -InputObject "Trusted Azure AD device record validation for inbound request failed, record with deviceId '$($DeviceID)' is disabled"
                    $StatusCode = [HttpStatusCode]::Forbidden
                    $Body = "Disabled device record"
                }
            }
            else {
                Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate signed content from client"
                $StatusCode = [HttpStatusCode]::Forbidden
                $Body = "Untrusted request"
            }
        }
        else {
            Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate certificate SHA256 hash value"
            $StatusCode = [HttpStatusCode]::Forbidden
            $Body = "Untrusted request"
        }
    }
    else {
        Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate certificate thumbprint"
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = "Untrusted request"
    }
}
else {
    Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not find device with deviceId: $($DeviceID)"
    $StatusCode = [HttpStatusCode]::Forbidden
    $Body = "Untrusted request"
}


######################################################################
#Region Reply
#Determine $Body. Could be from failure responses or JSON from correct reply.
if ($null -ne $ResponseArray){
    $body = $ResponseArray | ConvertTo-Json 
} else {
    $Body = $body  
}
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $body
})
#endregion