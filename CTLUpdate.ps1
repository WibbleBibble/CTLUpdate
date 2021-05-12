<#
.SYNOPSIS
  Script for backing up CA policies, creating/testing new policy sets and document existing policies
.DESCRIPTION
  Script for backing up CA policies, creating/testing new policy sets and document existing policies

.PARAMETER  Env
  Mandatory: True
  Description: Environment where you wish to initiate the action
  Possible values: DEV, PROD

.PARAMETER  Mode
  Mandatory: True
  Description: Action you wish to perform
  Possible values: backup, policyset,policycompare, document

.PARAMETER  Silent
  Mandatory: False
  Description: Verbose logging of API calls
  Possible values:  $True or $False

.EXAMPLE


Connect-Graph -Scopes "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory", "Application.Read.All" -ForceRefresh

.INPUTS
   <none>
.OUTPUTS
   <none>
.NOTES
    Script Name     : Set_AT_CTL.ps1
    Requires        : Powershell Version 5.0
    Tested          : Powershell Version 5.0
    Author          : 
    Version         : 2.1
    Date            : 2020-08-28 (ISO 8601 standard date notation: YYYY-MM-DD)

#>
#Requires -Version 5.1
#Requires -Modules AzureAD
#Requires -Modules ImportExcel
using namespace System.IO
#######################################################################################################################
[CmdletBinding()]