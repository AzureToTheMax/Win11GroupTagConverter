#Windows 11 Group Tag Converter Client Side Script

<#
.SYNOPSIS
Windows 11 Group Tag Converter Client Side Script
This script talks to the function app which changes clients from any existing group tag to a new defined X group tag for the sake of Windows 11 migrations.

.Description
1. Check to make sure it is a "Windows 11" Machine
2. Check to see what the last known tag reported by the Function App was. If it was the desired tag, use the wait period to prevent overly frequent check ins.
3. If needed (tag not set as needed, no record of what tag is, check in period exceeded) check in to the function app to verify or change tag
4. Log results

.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2023-03-26
Updated:     2023-05-07

            
Version history:
1 - 2023-03-26 - Creation
2 - 2023-05-07 - Updated to latest MSEndpointMGR authentication methods, credit to Nickolaj Andersen.  https://github.com/MSEndpointMgr/AADDeviceTrust
                 Updated log files to use UTC. 

#>



######################################################################
#Region Variables

#Your Windows 11 Group Tag
$DesiredGroupTag = "YOUR-AUTOPILOT-TAG"

#Once the right tag is set/confirmed, how many days should be waited before checking in with the Function app again.
$CheckInPeriod = 30

#Location to store files and name of the log file. You can not alter the name of the time marker or last known good tag file. All files are stored here.
$LogFileLocation = "C:\Windows\AzureToTheMax\Win11GTC"
$LogFileName = "Win11GroupTagConverter.Log"

#Function App URL
$AzureFunctionURL = "YOUR-FUNCTION-APP-URL"

#Delay Controller
$Delay = $true


#Testing values
#Export JSON instead of uploading for testing
$WriteLogFile = $false
#Ignore Time File - used for testing
$IgnoreTimeFile = $false

#endregion
######################################################################


######################################################################
#region functions
#Get-AzureADDeviceID
#Get-AzureADJoinDate
#Get-AzureADTenantID

function Get-AzureADDeviceID {
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoThumbprint -ne $null) {
            # Retrieve the machine certificate based on thumbprint from registry key
            $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
            if ($AzureADJoinCertificate -ne $null) {
                # Determine the device identifier from the subject name
                $AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                # Handle return value
                return $AzureADDeviceID
            }
            if ($AzureADJoinCertificate -eq $null) {
                $AzureADDeviceID = $AzureADJoinInfoThumbprint
                return $AzureADDeviceID
            }
        }
    }
} #endfunction 
function Get-AzureADJoinDate {
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoThumbprint -ne $null) {
            # Retrieve the machine certificate based on thumbprint from registry key
            $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
            if ($AzureADJoinCertificate -ne $null) {
                # Determine the device identifier from the subject name
                $AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                # Handle return value
                return $AzureADJoinDate
            }
            if ($AzureADJoinCertificate -eq $null) {
                $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -eq "CN=$($AzureADJoinInfoThumbprint)" }
                $AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                return $AzureADJoinDate
            }
        }
    }
} #endfunction 

#Function to get AzureAD TenantID
function Get-AzureADTenantID {
    # Cloud Join information registry path
    $AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
    # Retrieve the child key name that is the tenant id for AzureAD
    $AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
    return $AzureADTenantID
} #endfunction   

#endregion
######################################################################





######################################################################
#region Storage Directory

#Create storage dir if it does not exit
if (Test-Path $LogFileLocation) {
    write-host "Log File Location folder Folder exists already."
    } else {
    New-Item $LogFileLocation -ItemType Directory -force -ErrorAction SilentlyContinue > $null 
    $folder = Get-Item "$LogFileLocation" 
    $folder.Attributes = 'Directory','Hidden' 
    }
#Endregion
######################################################################





######################################################################
#region script


Add-Content "$($LogFileLocation)\$($LogFileName)" "
$((get-date).ToUniversalTime()): Info: Windows 11 Group Tag Converter starting." -Force

# Validate that the script is running on an Azure AD joined or hybrid Azure AD joined device
if (Test-AzureADDeviceRegistration -eq $true) {
    Add-Content "$($LogFileLocation)\$($LogFileName)" "$((get-date).ToUniversalTime()): Info: Confirmed this is a AAD Joined or Hybrid AAD joine device." -Force
}
else {
    Write-Warning -Message "Script is not running on an Azure AD joined or hybrid Azure AD joined device"
    Add-Content "$($LogFileLocation)\$($LogFileName)" "$((get-date).ToUniversalTime()): Warning: Script is not running on an Azure AD joined or hybrid Azure AD joined device." -Force
    #This script should never run on such a device
    exit 1
}


# Use TLS 1.2 connection when calling Azure Function
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Install required modules
Install-Module -Name "AADDeviceTrust.Client" -Force

#Get Current date in UTC
$DateCurrentUTC = (Get-Date).ToUniversalTime()
#Get Computer Info
$ComputerInfo = Get-computerInfo
#Get OS Name
$ComputerOSName = $ComputerInfo.OSName
#Get Computer model
$ComputerModel = $ComputerInfo.CSModel
#Get Serial Number
$SerialNumber = $ComputerInfo.BiosSeralNumber
#Get Computer Name
$ComputerName = $ComputerInfo.Csname
#Get Azure Device ID
$AzureADDeviceID = Get-AzureADDeviceID
#Get Azure Tenant
$AzureADTenantID = Get-AzureADTenantID


#Check for Win11
If ($ComputerOSName -like "*Windows 11*"){
    #Check for Virtual Machine
    if ($ComputerModel -notlike "*Virtual*"){

     
        if($IgnoreTimeFile -eq $false){

            #Check what we last knew the tag to be
           
           if(Test-Path "$($LogFileLocation)\lastKnownAutopilotTag.txt"){
            $LastKnownTag = get-content "$($LogFileLocation)\lastKnownAutopilotTag.txt"
            } else {
            $LastKnownTag = "NULL"  
            }

           if ($LastKnownTag -eq $DesiredGroupTag) {
                Write-host "Last known tag of $($LastKnownTag) matches the desired tag of $($DesiredGroupTag). Time tracking will be enforced."
                Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Last known tag of $($LastKnownTag) matches the desired tag of $($DesiredGroupTag). Time tracking will be enforced." -Force
                #Only process time tracking (wait to check in) if the last known tag was what we still want it to be.

                #Check for Marker files
                $TestTimeMarker = Test-Path "$($LogFileLocation)\TimeMarker.txt"
                if ($TestTimeMarker -eq $true) {
                write-host "Time Marker File located! Running Calculation!"
                Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Info: Time Marker File located! Running Calculation!" -Force

                #Get Content of time marker file
                $MarkerFileTimeUTC = Get-Content "$($LogFileLocation)\TimeMarker.txt"

                #If file content is Null
                if($MarkerFileTimeUTC -eq $null){
                #If marker file existed but was null. This will cause a device to not check in until next run.
                Write-Warning "Marker File Content Null? Using current UTC!"
                Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Warning: Time Marker File existed but content was null? Using current UTC!" -Force
                Set-Content "$($LogFileLocation)\TimeMarker.txt" "$($DateCurrentUTC)" -Force
                $MarkerFileTimeUTC = $DateCurrentUTC
                }

                #Check/calculate time range
                $Difference = NEW-TIMESPAN -Start $MarkerFileTimeUTC -End $DateCurrentUTC
                $Difference = $Difference.TotalDays
                if ($Difference -lt "$($CheckInPeriod)"){
                    #If check in period has NOT been exceeded
                    Write-host "It has been less than the check in period of $($CheckInPeriod) days since last run. Exiting!"
                    Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Info: It has been less than the check in period of $($CheckInPeriod) days since last run. Exiting!" -Force
                    exit 0
                } else {
                    #If check in period has been exceeded
                    Write-host "It has been MORE than the check in period of $($CheckInPeriod) days since last run. Continuing!"
                    Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Info: It has been MORE than the check in period of$($CheckInPeriod) days since last run. Continuing!" -Force
                }
                
                } else {
                #If time marker file was not found
                Write-Warning "Time Marker File not found! Generating file!"
                Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Warning: Time Marker File not found. Generating file with time of $($DateCurrentUTC)!" -Force
                #Generate our time marker file with a marker of script start.
                New-Item "$($LogFileLocation)\TimeMarker.txt" -ItemType file -ErrorAction SilentlyContinue > $null 
                #Hide the file
                $File = Get-Item "$($LogFileLocation)\TimeMarker.txt" 
                $File.Attributes = 'Hidden' 
                #Place time of now in UTC
                Set-Content "$($LogFileLocation)\TimeMarker.txt" "$($DateCurrentUTC)" -Force
                }

            } else {
            #If desired group tag does not match last known tag, skip time tracking and connect now.
            Write-host "Last known tag of $($LastKnownTag) does NOT match the desired tag of $($DesiredGroupTag). Time tracking will NOT be enforced."
            Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Last known tag of $($LastKnownTag) does NOT match the desired tag of $($DesiredGroupTag). Time tracking will NOT be enforced." -Force
            }
    
        } else {
        #If $IgnoreTimeFile is true, we don't need to look at any of the time marker code.
        Write-Warning "Script is set to ignore the time file!"
        Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Warning: Script is set to ignore the time file!" -Force
        }

    
        
            if ($WriteLogFile){
            Write-host "writing log file"
            New-Item C:\Temp -ItemType Directory -ErrorAction SilentlyContinue > $null 
            $FunctionCallJSON  | Out-File "C:\Temp\Windows11GroupTagConverter.json"
            Write-host "Log File Enabled - Not sending!"
            exit 1
        
            } else {
        
            #Write upload intent to console
            Write-Output "Sending Payload..."
                #Randomize over 50 minutes to spread load on Azure Function - disabled on date of enrollment 
                $JoinDate = Get-AzureADJoinDate
                $DelayDate = $JoinDate.AddDays(1)
                $CompareDate = ($DelayDate - $JoinDate)
                if ($CompareDate.Days -ge 1){
                    if($Delay -eq $true){
                        $ExecuteInSeconds = (Get-Random -Maximum 3000 -Minimum 1)
                        Write-Output "Delay enabled - Randomzing execution time by $($ExecuteInSeconds)"
                        Start-Sleep -Seconds $ExecuteInSeconds
                        }
                    }
            #Function App Upload Commands - Send the data! 
            # Create body for Function App request
            $BodyTable = New-AADDeviceTrustBody

            # Optional - extend body table with additional data
            $BodyTable.Add("SerialNumber", "$($SerialNumber)")
            $BodyTable.Add("DesiredGroupTag", "$($DesiredGroupTag)")

            # Construct URI for Function App request
            $Response = Invoke-RestMethod -Method "POST" -Uri $AzureFunctionURL -Body ($BodyTable | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
            
            #Check response for indication of change. If present, verify correct tag and computername in the response.
            if ($Response -like "*changed to*"){
                if ($response.DesiredGroupTag -eq $DesiredGroupTag -and $response.ComputerName -eq $ComputerName){
                    Write-host "Response indicates change and matches requested tag and requested device."
                    Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Info: Response indicates change and matches requested tag and requested device." -Force
                }
                else {
                    Write-error "Response indicates change but does NOT match requested tag and/or requested device."
                    Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Error: Response indicates change but does NOT match requested tag and/or requested device." -Force
                }
            }

            }
    
    } else {
        Write-Error "This is a virtual machine, ending!"
        Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Error: This is a virtual Machine, ending!" -Force
        exit 1
    }


} else {
    Write-Error "This is not a Windows 11 Machine!"
    Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): Error: This is not a Windows 11 machine, ending!" -Force
    exit 1
}

#endregion

#region Parse response

    #Report back status
    $date = Get-Date -Format "dd-MM HH:mm"
    $OutputMessage = "Group Tag Change:$($date) "
    

        if ($Response -match "200") {
        
            $OutputMessage = $OutputMessage + " Status:OK " + $Response
            #Log The tag only on success
            Set-Content "$($LogFileLocation)\lastKnownAutopilotTag.txt" "$($Response.CurrentGroupTag)" -Force
        } else {
            $OutputMessage = $OutPutMessage + " Status:Failure " + $Response
        }
    

    Write-Output $OutputMessage
    Add-Content "$($LogFileLocation)\$($LogFileName )" "$((get-date).ToUniversalTime()): info: Output message is $($OutputMessage)" -Force
    Exit 0
#endregion