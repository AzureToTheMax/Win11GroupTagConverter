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
Updated:     2023-05-07
            
Version history:

1 - 2023-03-26 - Creation
2 - 2023-05-07 - Updated to latest MSEndpointMGR authentication methods. Credit to NickolajA

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
$MyComputerName = "YOUR-PC-NAME" #Your Computer Name
    if ($RunningComputerName -eq $MyComputerName){
          
        #Set Running enviroment variable as Local
        $RunLocation = "Local"

        #The location of your CSV file containing headers and information for the below variables.
        $SecretsCSV = Import-Csv "C:\PATH-TO\Secrets.csv"

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
$DeviceID = $Request.Body.DeviceID #From AADDeviceTrust
$Signature = $Request.Body.Signature #From AADDeviceTrust
$Thumbprint = $Request.Body.Thumbprint #From AADDeviceTrust
$PublicKey = $Request.Body.PublicKey #From AADDeviceTrust




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
    if (Test-AzureADDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $AzureADDeviceRecord.alternativeSecurityIds.key -Type "Thumbprint" -Value $Thumbprint) {
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