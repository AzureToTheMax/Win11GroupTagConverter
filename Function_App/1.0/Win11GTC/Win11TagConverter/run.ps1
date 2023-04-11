#Windows 11 Group Tag Converter Function App

<#
.SYNOPSIS
Windows 11 Group Tag Converter Function App
This is the Function App which receives client requests and processes confirmation or alteration of the client devices group tag

.Description
1. Receive a request and pull out the information
2. Confirm the requesting device listed the right tenant ID, a valid Azure AD device, and that Azure AD device is enabled.
3. Check the group tag of that current SN
4. If already correct, reply as such
5. Otherwise, change the tag and let the device know.

.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2023-03-26
Updated:
This is a somewhat hevaily modified version of the Log Analytics Function App by the MSEndpointMGR team.
            
Version history:
1 - 2023-03-26 - Creation

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
    Returns a raw bearer token.

.NOTES
    Author:      Maxton Allen
    Contact:     @AzureToTheMax
    Created:     2023-02-17
    Updated:     2023-02-17

    Version history:
    1 (2023-02-17) Function created
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
        return $Response.access_token 
    } 
    Else { 
        Throw "Authentication failed" 
    } 
} #End function




#endregion functions
######################################################################


#Start Script
Write-Information "Windows 11 Group Tag Converter received a request."

# Setting inital Status Code: 
$StatusCode = [HttpStatusCode]::OK



######################################################################
#region Variables
# Define variables from Function App Configuration
$TenantID = $env:TenantID #Your Tenant ID

<#
.Description
If you had to use an App registration alone, you could swap out all instance of self-auth funciton calls with AppReg function calls and use the below to tell the Function those values.
You would want to use a key vault for the secret.

# Get secrets from Keyvault
$appId = $env:appId #Enterprise App Registrations App ID
$appSecret = $env:appSecret #Your Registered Apps Secret Key Value
#>



#This allows you to run the app in visual. 
#You need an App Registration with the same permissions as the Function and you need those values in a CSV file on your system.
#CSV is better than directly in code - that way you can push code without redacting keys and secrets.
$RunningComputerName = $env:COMPUTERNAME
$MyComputerName = "PC-NAME" #Your Computer Name
    if ($RunningComputerName -eq $MyComputerName){
          
        #Set Running as Local
        $RunLocation = "Local"

        #The location of your CSV file containing headers and information for the below variables.
        $SecretsCSV = Import-Csv ".\Secrets.csv"

        #See Above Section for explination on values
        $appId = $SecretsCSV.Appid
        $appSecret = $SecretsCSV.AppSecret
        $TenantID = $SecretsCSV.TenantID

        } else {
            #Set our token method to cloud (It's the Function App)
            $RunLocation = "Cloud"
        }



#Extract variables from payload with information on what needs to happen
$InboundDeviceID= $Request.Body.AzureADDeviceID #The Azure Device ID of the inbound device
$InboundTenantID = $Request.Body.AzureADTenantID #The Tenant ID reported by the device 
$SerialNumber = $Request.Body.SerialNumber #The Serial Number of the device
$DesiredGroupTag = $Request.Body.DesiredGroupTag #The tag to change to
$RequestingComputerName = $Request.Body.ComputerName #The full name of the requesting computer

#endregion
######################################################################



######################################################################
#region Process

$LogsReceived = New-Object -TypeName System.Collections.ArrayList
foreach ($Key in $MainPayLoad.Keys) {
    $LogsReceived.Add($($Key)) | Out-Null
}

# Write logging output.
Write-Information "Request recieved from $($RequestingComputerName)"
Write-Information "Inbound DeviceID $($InboundDeviceID)"
Write-Information "Inbound TenantID $($InboundTenantID)"
Write-Information "Environment TenantID $TenantID"

# Declare response object as Arraylist
$ResponseArray = New-Object -TypeName System.Collections.ArrayList

# Verify request comes from correct tenant
if($TenantID -eq $InboundTenantID){
    Write-Information "Request is comming from correct tenant"


    # Retrieve authentication token either via cloud or local (app reg)
    if($RunLocation -eq "Cloud"){
        #Use Function permissions to get Graph token
        write-host "Graph Call - Running as Cloud: Using Self-Authentication"
        $Script:AuthToken = Get-SelfGraphAuthToken
    } else {
        #Use app reg for Graph token
        #Slightly complicated as Get-SelfGraphAuthToken returns a formated bearer token, where as Get-AppRegGraphToken is just the token which is the format needed later
        write-host "Graph Call - Running as Local: Using App Registration"
        $Credential = New-Object System.Management.Automation.PSCredential($AppID, (ConvertTo-SecureString $AppSecret -AsPlainText -Force)) 
        $Token = Get-AppRegGraphToken -credential $Credential -TenantID $TenantID 
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $Token"
        }
        $Script:AuthToken = $AuthenticationHeader 
    }

    
    # Query graph for device verification 
    $DeviceURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($InboundDeviceID)'"
    $DeviceIDResponse = (Invoke-RestMethod -Method "Get" -Uri $DeviceURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value

    # Assign to variables for matching 
    $DeviceID = $DeviceIDResponse.deviceId  
    $DeviceEnabled = $DeviceIDResponse.accountEnabled    
    Write-Information "DeviceID $DeviceID"   
    Write-Information "DeviceEnabled: $DeviceEnabled"

    # Verify request comes from a valid device
    if($DeviceID -eq $InboundDeviceID){
        Write-Information "Request is coming from a valid device in Azure AD"
        if($DeviceEnabled -eq "True"){
            Write-Information "Requesting device is not disabled in Azure AD"                       
                Write-Information "Processing request for $($RequestingComputerName)"

                #Query Graph for current Device Group Tag
                #You need the SN and DeviceManagementServiceConfig.ReadWrite.All permission
                $graphApiVersion = "beta"
                $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
                $encoded = [uri]::EscapeDataString($SerialNumber)
                $AutoPilotInfouri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=contains(serialNumber,'$encoded')"
                $GroupTagResponse = (Invoke-RestMethod -Method "Get" -Uri $AutoPilotInfouri -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value
                $CurrentGroupTag = $GroupTagResponse.groupTag
                $DeviceAutopilotID = $GroupTagResponse.ID
               
                #This is a converter from A to B so it should never have a null value
                if ($CurrentGroupTag -ne $null) {
                    if ($CurrentGroupTag -eq $DesiredGroupTag){
                        #already under the right tag
                        Write-Information "$($RequestingComputerName) is already under $($DesiredGroupTag)"
                            $PSObject = [PSCustomObject]@{
                                ComputerName = $RequestingComputerName
                                CurrentGroupTag = $CurrentGroupTag
                                Response = "200: Device is already under requested Group Tag $($DesiredGroupTag)"
                            }    
                        $ResponseArray.Add($PSObject) | Out-Null
                        $StatusCode = [HttpStatusCode]::OK

                        } else {
                        #Request graph to change the tag
                        Write-Information "$($RequestingComputerName) is currently under tag $($CurrentGroupTag). Changing to tag $($DesiredGroupTag)"
                        $graphApiVersion = "beta"
                        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$DeviceAutopilotID/UpdateDeviceProperties"
                        $json = "{"
                        $json = $json + " groupTag: `"$DesiredGroupTag`""
                        $json = $json + " }"
                        $GroupTagResponse = (Invoke-WebRequest -Method "POST" -Uri $uri -ContentType "application/json" -Headers $Script:AuthToken -Body $json -ErrorAction Stop).StatusCode

                        $PSObject = [PSCustomObject]@{
                            ComputerName = $RequestingComputerName
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
                        ComputerName = $RequestingComputerName
                        Response = "400: CurrentGroupTag for requesting device $($RequestingComputerName) is null!"
                    }    
                    $StatusCode = [HttpStatusCode]::Forbidden
                    $ResponseArray.Add($PSObject) | Out-Null
                }
        }
        else{
            Write-Warning "Device is not enabled - Forbidden"
            $StatusCode = [HttpStatusCode]::Forbidden
        }
    }
    else{
        Write-Warning  "Device not in my Tenant - Forbidden"
        $StatusCode = [HttpStatusCode]::Forbidden
    }
}
else{
    Write-Warning "Tenant not allowed - Forbidden"
    $StatusCode = [HttpStatusCode]::Forbidden
}
#endregion
######################################################################

######################################################################
#Region Reply
$body = $ResponseArray | ConvertTo-Json 
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $body
})
#endregion