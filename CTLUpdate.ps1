<#
.SYNOPSIS
  Script for setting global policy for ATs in Azure AD
.DESCRIPTION
  Script will:
  Check for existence of policy already and do nothing if it matches (idompotency)
  If no policy or no match for desired state we will set t

.PARAMETER  ATinMins
  Mandatory: True
  Description: Value in minutes for AT maximum. Must be less than 60 or less and greater than 10.
  Possible values: Integer 

.PARAMETER  TestAction
  Mandatory: False
  Description: Determines if a test action is required. Only needed for test tenant.
  Switch variable.

.EXAMPLE

-Set_AT_CTL.ps1 -ATinMins 60 -TestAction

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
    [Parameter(Mandatory = $true,Position = 0)]
    [string]$UPN,
    [Parameter( Mandatory = $false,Position = 1)]
    [switch]$Test
)

function GetExistingJWT ($requiredtimeinmins, $TargetAPI, $TargetUserUPN){
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
          $utcTime = $orig.AddSeconds($decodedToken.exp)
          $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
          $localTime = $utcTime.AddMinutes($offset)     # Return local time,

          $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $localTime
          # Time to Token Expiry
          $timeToExpiry = ($localTime - (get-date))
          $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry
          #Measure against the offset we'll allow
          if($decodedToken.timeToExpiry.totalminutes -gt $requiredtimeinmins){
              write-host "Current time remaining on the AT is: $($decodedToken.timeToExpiry.minutes) minutes $($decodedToken.timeToExpiry.seconds) seconds" -fore green
              return $JWT
          }
      }
  }    
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
$Script:Reportfile = $Outputpath, "\AAD_Write_CTL_Configure.txt" -join ""
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
        WriteFailureandExit -ErrMessage "FAIL: Prerequisites not installed ($($AADModuleName) PowerShell module not installed)"
    }
}

$ATTimeSpan = New-TimeSpan -Minutes $ATinMins
$ShortNotationATTimeSpan = "{0}" -f $ATTimeSpan
#Get existing policy - check for an existing org default
try{
  $PolicyCount = (Get-AzureADPolicy | ?{$_.IsOrganizationDefault -ne $true -and $_.type -eq "TokenLifetimePolicy"}).count
}catch{
  WriteFailureandExit -ExceptionOutput $_.Exception.Message -ErrMessage "ERROR: Failed to read existing AAD policies. Cannot continue"
}
if($PolicyCount -gt 0){
  #Get name
  $PolicyName = (Get-AzureADPolicy | ?{$_.IsOrganizationDefault -ne $true -and $_.type -eq "TokenLifetimePolicy"} | select DisplayName)
  WriteFailureandExit -ErrMessage  "ERROR: There is already a default policy which is org default for tokenlifetimes: '$($PolicyName)'!"
}

#If we need to test first then we will set the new policy -5
if($Test){
  $TestMins =($ATinMins-5)
  $TestTimeSpan = New-TimeSpan -Minutes $TestMins
  $ShortNotationTestTimeSpan = "{0}" -f $TestTimeSpan
  $TestAADPolicyName = "JPMC_AccessTokens_$($TestMins)mins"
  try{
    $TestPolicy = New-AzureADPolicy -Definition @('{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"'+$ShortNotationTestTimeSpan+'"}}') -DisplayName $TestAADPolicyName -IsOrganizationDefault $true -Type "TokenLifetimePolicy"
  }catch{
    WriteFailureandExit -ExceptionOutput $_.Exception.Message -ErrMessage "ERROR: Failed to create the TEST CTL AAD policy!"
  }
  #Now connect and verify that the policy setting is correct. Get a JWT for MSGraph
  $JWT = get-newJWT -resourceURI $MSGraphAppID -authority $MSLoginEndpoint -clientId $UniversalPSAppID -UserUPN $UPN
  #Now check expiry time matches desired TEST time


}


# Attempt to Create new policy
try{
  $NewPolicy = New-AzureADPolicy -Definition @('{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"'+$ShortNotationATTimeSpan+'"}}') -DisplayName "JPMC_AccessTokens_$($ATinMins)mins" -IsOrganizationDefault $false -Type "TokenLifetimePolicy"
}catch{
  WriteFailureandExit -ExceptionOutput $_.Exception.Message -ErrMessage "ERROR: Failed to create the CTL AAD policy!"
}





}catch{
  WriteFailureandExit($_.Exception.Message,"ERROR: Failed to create the SP!"){
}