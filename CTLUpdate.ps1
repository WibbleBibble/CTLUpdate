<#
.SYNOPSIS
  Script for setting global policy for ATs in Azure AD
.DESCRIPTION
  Script will:
  Check for existence of policy already and do nothing if it matches (idompotency)
  If no policy or no match for desired state we will either
    Set test policy (if switch argument is true), 
      test that the test policy value (target-5 minutes) results in an AT with the correct value
      delete test policy
      wait X mins
    Write target state policy
    Test that target policy was written, but not that the AT time has changed

.PARAMETER  ATinMins
  Mandatory: True
  Description: Value in minutes for AT maximum. Must be less than 60 or less and greater than 10.
  Possible values: Integer 

.PARAMETER  TestAction
  Mandatory: False
  Description: Determines if a test action is required. Only needed for test tenant.
  Switch variable.

.EXAMPLE

-Set_AT_CTL.ps1 -ATinMins 60 -UPN joe.bloggs@joebloggs.com -Test

.INPUTS
   <none>
.OUTPUTS
   <none>
.NOTES
    Script Name     : Set_AT_CTL.ps1
    Requires        : Powershell Version 5.0
    Tested          : Powershell Version 5.0
    Author          : 
    Version         : 1.0
    Date            : 2021-05-12 (ISO 8601 standard date notation: YYYY-MM-DD)

#>
#Requires -Version 5.0
#Requires -Modules AzureADPreview
#######################################################################################################################
[CmdletBinding()]

Param(

    [Parameter(Mandatory = $true,Position = 0)]
    [ValidateRange(10, 60)]
    [int]$ATinMins,
    [Parameter(Mandatory = $true,Position = 1)]
    [string]$UPN,
    [Parameter( Mandatory = $false,Position = 2)]
    [switch]$Test,
    [Parameter( Mandatory = $false,Position = 3)]
    [ValidateRange(10,300)]
    [int]$Sleep=30
)

function CheckATValidityPeriod ($requiredtimeinmins, $TargetAPI, $TargetUserUPN){
    #sleep to allow tokens to be captured properly
    sleep 10
    try{
        $cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared
    }catch{
        return "NONE"
    }
    #Get all tokens that match the TargetAPI and UPN which was passed
    $validtokens = $cache.ReadItems() | ?{($_.Resource -eq $TargetAPI) -and ($_.DisplayableId -eq $TargetUserUPN)}
    if($validtokens){
        foreach($JWT in $validtokens){
            #Check each token that was issued for our target API
            $token = $JWT.accesstoken
            if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
            # Token
            foreach ($i in 0..1) {
                $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
                switch ($data.Length % 4) {
                    0 { break }
                    2 { $data += '==' }
                    3 { $data += '=' }
                }
            }
            $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json 
            Write-Verbose "JWT Token:"
            Write-Verbose $decodedToken
            # Signature
            foreach ($i in 0..2) {
                $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
                switch ($sig.Length % 4) {
                    0 { break }
                    2 { $sig += '==' }
                    3 { $sig += '=' }
                }
            }
            Write-Verbose "JWT Signature:"
            Write-Verbose $sig
            $decodedToken | Add-Member -Type NoteProperty -Name "sig" -Value $sig
            # Convert Expiry time to PowerShell DateTime
            $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
            $timeZone = Get-TimeZone
            $expTime = $orig.AddSeconds($decodedToken.exp)
            $nbfTime = $orig.AddSeconds($decodedToken.nbf)
            $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
            $explocalTime = $expTime.AddMinutes($offset)     # Return exp local time,
            #$nbflocalTime = $nbfTime.AddMinutes($offset)     # Return exp local time,

            $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $explocalTime
            # Time to Token Expiry
            $timeToExpiry = ($explocalTime - (get-date))
            $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry]
            $validityperiodinmins = ($expTime -$nbfTime).TotalMinutes-5
            #Check for expected time in the AT
            if($validityperiodinmins -ne $requiredtimeinmins){
                Write-host "ERROR: The EXPECTED token validity period is $($requiredtimeinmins) minutes, the ACTUAL validity period is: $($validityperiodinmins)" -fore Red
                return "MISMATCH"
            }else{
            write-host "OK: Access Token validity period is $($requiredtimeinmins) minutes as expected" -fore Green
            return "OK"
            }
        }
    }   
    Write-host "ERROR: Failed to locate the Access Token which was just created, unable to validate setting is as desired." -fore Red
    return "NONE"
}

Function get-newJWT ($resourceURI, $authority, $clientId,$UserUPN) {
  #Parameters
  $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
  $adal = Join-Path $AADModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
  $adalforms = Join-Path $AADModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
  [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
  [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
  $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
  # Get token by prompting login window. User UPN we already have (if we have one)
  $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always"
  if($null -ne $UserUPN){
      $PopulatedUserID = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserUPN,1
      $authResult = $authContext.AcquireTokenAsync($resourceURI, $ClientID, $RedirectUri, $platformParameters,$PopulatedUserID)
  }else{
      $authResult = $authContext.AcquireTokenAsync($resourceURI, $ClientID, $RedirectUri, $platformParameters)
  }
  if($null -ne $authResult){return $authResult}else{return "FAIL"}
}

Function WriteFailureandExit($ExceptionOutput,$ErrMessage){
  if($ExceptionOutput){$ExceptionName = $ExceptionOutput.exception.errorcontent.message.value}
  EchoandLog -TXT "ERROR: $($ErrMessage)" -col "Red" -OUTPUTFILE $Reportfile
  if($ExceptionOutput){EchoandLog -TXT $ExceptionName -col "Red" -OUTPUTFILE $Reportfile}
  Stop-Transcript 
  exit
}

function EchoandLog($TXT,$COL,$OUTPUTFILE,$NONEWLINE){
  #Lazy function
  if(-not $COL){$COL = "White"}
  if($NONEWLINE){
      Write-Host $TXT -f $COL -n; $TXT
  }else{
      Write-Host $TXT -f $COL; $TXT
  }
}

function KillATs($APIName){
   try{
      $cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared
  }catch{
      return
  }
  #Get all tokens that match the TargetAPI and UPN which was passed
  $validtokens = $cache.ReadItems() | ?{($_.Resource -eq $APIName) -and ($_.DisplayableId -eq $UPN)}
  if($null -ne $validtokens){
    try{
        $cache.DeleteItem($validtokens) | out-null
    }catch{}
  }
}

function CreateAADTokenPolicy($ShortNotationValidity,$PolicyName,$Hardfail){
    try{
        $NewPolicy = New-AzureADPolicy -Definition @('{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"'+$ShortNotationValidity+'"}}') -DisplayName $PolicyName -IsOrganizationDefault $true -Type "TokenLifetimePolicy"
    }catch{
        if($hardfail -eq $true){
            WriteFailureandExit -ExceptionOutput $_.Exception.Message -ErrMessage "Failed to create the $($PolicyName) policy!"
        }else{
            write-host "$($_.Exception.Message) ERROR: Failed to create the $($PolicyName) AAD policy!" -ForegroundColor red
        }
    }
    write-host "Created new policy: $PolicyName with Id $($NewPolicy.Id)" -fore Green
    write-host "Waiting $PolicySleepTime secs for new policy to bind..."
    sleep $PolicySleepTime
    return $NewPolicy
}

function DeleteAADTokenPolicy($PolicyToDelete){
    try{
        Remove-AzureADPolicy -Id $PolicyToDelete.Id
    }catch{
        WriteFailureandExit -ExceptionOutput $_.Exception.Message -ErrMessage "Failed to delete the $($PolicyToDelete.Displayname) policy!"
    }
    write-host "Deleted policy: $($PolicyToDelete.displayname) with Id $($PolicyToDelete.Id)" -fore Green
}

##### END FUNCTIONS
### START CONSTANTS
$scriptPath = $myInvocation.MyCommand.Path
$scriptFolder = Split-Path $scriptPath
$Outputpath = $scriptFolder
$MSGraphAppID = "00000003-0000-0000-c000-000000000000"
$AADGraphAppID = "00000002-0000-0000-c000-000000000000"
$UniversalPSAppID = "1b730954-1685-4b74-9bfd-dac224a7b894"
$MSLoginEndpoint = "https://login.microsoftonline.com/common"
$AADAuthFailureMsg = "One or more errors occurred."
$AADModuleName = "AzureADPreview"
$Script:Reportfile = $Outputpath, "\AAD_Write_CTL_$($ATinMins)_mins.txt" -join ""
$PolicySleepTime = $Sleep
Start-Transcript $Reportfile -Force
##Add systemproxy stuff here..
#######################################

#Attempt to import AzureAD module
#pre-requisites
$Script:AADModule = get-module -name $AADModuleName
if($null -eq $AADModule){
    try {
        $Script:AADModule = Import-Module -Name $AADModuleName -ErrorAction Stop -PassThru
    }
    catch {
        WriteFailureandExit -ErrMessage "Prerequisites not installed ($($AADModuleName) PowerShell module not installed)"
    }
}

#Is there a valid AAD connection already?
try{
  $Test= Get-AzureADTenantDetail -ErrorAction SilentlyContinue
}catch{}

if(-not $test.ObjectId){
  #Connect to AAD
  try{
      connect-azuread | out-null
  }catch{
      WriteFailureandExit -ErrMessage "Unable to connect to AzureAD using the PowerShell module using current credentials."
  }
}

$ATTimeSpan = New-TimeSpan -Minutes $ATinMins
$ShortNotationATTimeSpan = "{0}" -f $ATTimeSpan
#Get existing policy - check for an existing org default
try{
  $PolicyCount = (Get-AzureADPolicy | ?{$_.IsOrganizationDefault -ne $true -and $_.type -eq "TokenLifetimePolicy"}).count
}catch{
  WriteFailureandExit -ExceptionOutput $_.Exception.Message -ErrMessage "Failed to read existing AAD policies. Cannot continue"
}
if($PolicyCount -gt 0){
  #Get name of any conflicting policies
  $PolicyName = (Get-AzureADPolicy | ?{$_.IsOrganizationDefault -eq $true -and $_.type -eq "TokenLifetimePolicy"} | select DisplayName)
  if($null -ne $PolicyName){WriteFailureandExit -ErrMessage "There is already a policy which is org default for tokenlifetimes: '$($PolicyName.displayname)'!"}
}


#If we need to test first then we will set the new policy -5
if($Test){
  write-host "Creating Test policy to validate setting works - Test used because the policy override is the same as old default..."
  $TestMins = ($ATinMins-5)
  $TestTimeSpan = New-TimeSpan -Minutes $TestMins
  $ShortNotationTestTimeSpan = "{0}" -f $TestTimeSpan
  $TestAADPolicyName = "JPMC_AccessTokens_$($TestMins)mins"
  $TestPolicy = CreateAADTokenPolicy -ShortNotationValidity $ShortNotationTestTimeSpan -PolicyName $TestAADPolicyName -Hardfail $true

  #Now connect and verify that the policy setting is correct. Get a JWT for MSGraph
  #Kill any existing first
  KillATs -APIName $MSGraphAppID 

  #Get new AT
  $JWT = get-newJWT -resourceURI $MSGraphAppID -authority $MSLoginEndpoint -clientId $UniversalPSAppID -UserUPN $UPN
  #Now check expiry time matches desired TEST time
  $MSGraphJWT= CheckATValidityPeriod -requiredtimeinmins $TestMins -TargetAPI $MSGraphAppID -TargetUserUPN $UPN
  if($MSGraphJWT -ne "OK"){
    #Cleanup
    write-host "Validation failure, deleting policy.."
    DeleteAADTokenPolicy -PolicyToDelete $TestPolicy
    Stop-Transcript 
    exit
  }else{
    #Cleanup - delete the test policy. We don't need it now
     DeleteAADTokenPolicy -PolicyToDelete $TestPolicy
  }
}

### How much time do we have here?

# Attempt to create the FINAL policy
write-host "Creating main policy..."
$AADPolicyName = "JPMC_AccessTokens_$($ATinMins)mins"
$AADPolicy = CreateAADTokenPolicy -ShortNotationValidity $ShortNotationATTimeSpan -PolicyName $AADPolicyName -Hardfail $true
#Kill existing..
KillATs -APIName $MSGraphAppID 

#Get new and test!
$JWT = get-newJWT -resourceURI $MSGraphAppID -authority $MSLoginEndpoint -clientId $UniversalPSAppID -UserUPN $UPN
#Now check expiry time matches desired TEST time
$MSGraphJWT= CheckATValidityPeriod -requiredtimeinmins $ATinMins -TargetAPI $MSGraphAppID -TargetUserUPN $UPN
if($MSGraphJWT -ne "OK"){
    #Cleanup
    write-host "Validation failure, deleting policy.."
    DeleteAADTokenPolicy -PolicyToDelete $TestPolicy
    Stop-Transcript 
    exit
}
write-host "SUCCESS: Policy created as required"
Stop-Transcript