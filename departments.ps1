#####################################################
# HelloID-Conn-Prov-Source-Infor-HCM-Departments
#
# Version: 1.0.0.0
#####################################################

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

$c = $configuration | ConvertFrom-Json

$authurl = $c.authurl
$queryurl = $c.queryurl
$clientId = $c.clientid
$clientSecret = $c.clientsecret
$user = $c.username
$pw = $c.password

# Set debug logging
switch ($($c.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

Write-Information "Start department import"

#region functions

function New-InforSession {
    [CmdletBinding()]
    param (
        [Alias("Param1")] 
        [parameter(Mandatory = $true)]  
        [string]      
        $clientId,

        [Alias("Param2")] 
        [parameter(Mandatory = $true)]  
        [string]
        $clientSecret,

        [Alias("Param3")] 
        [parameter(Mandatory = $true)]  
        [string]
        $user,

        [Alias("Param4")] 
        [parameter(Mandatory = $true)]  
        [string]
        $pw,

        [Alias("Param5")] 
        [parameter(Mandatory = $true)]  
        [string]
        $authurl
    )

    try {
        # Set TLS to accept TLS, TLS 1.1 and TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

        $authorisationBody = @{
            'grant_type'    = "password"
            'client_id'     = $ClientId
            'client_secret' = $ClientSecret
            'username'      = $user
            'password'      = $pw
        }        
        $splatAccessTokenParams = @{
            Uri             = $authurl
            Headers         = @{'Cache-Control' = "no-cache" }
            Method          = 'POST'
            ContentType     = "application/x-www-form-urlencoded"
            Body            = $authorisationBody
            UseBasicParsing = $true
        }

        Write-Verbose -verbose "Creating Access Token at uri '$($splatAccessTokenParams.Uri)'"

        $result = Invoke-RestMethod @splatAccessTokenParams -Verbose:$false
        
        if ($null -eq $result.access_token) {
            throw $result
        }

        $Script:expirationTimeAccessToken = (Get-Date).AddSeconds($result.expires_in)
        $Script:AccessToken = $($result.access_token)

        Write-Verbose -verbose "Successfully created Access Token at uri '$($splatAccessTokenParams.Uri)'"
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Write-Verbose -verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error creating Access Token at uri ''$($splatAccessTokenParams.Uri)'. Please check credentials. Error Message:"
                IsError = $true
            })     
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function Confirm-AccessTokenIsValid {
    if ($null -ne $Script:expirationTimeAccessToken) {
        if ((Get-Date) -le $Script:expirationTimeAccessToken) {
            return $true
        }
    }
    return $false
}

function Invoke-InforWebRequestList {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false)]
        [string]
        $Url
    )
    
    # Set TLS to accept TLS, TLS 1.1 and TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

    try {
        $accessTokenValid = Confirm-AccessTokenIsValid
        if ($true -ne $accessTokenValid) {
            New-InforSession -clientID $clientID -clientSecret $clientSecret -user $user -pw $pw -authurl $authurl
        }
           
        $splatGetDataParams = @{
            Uri             = "$Url&access_token=$Script:AccessToken"
            Method          = 'GET'
            ContentType     = "application/json"
            UseBasicParsing = $true
        }
    
        Write-Verbose -verbose "Querying data from Infor"

        $result = Invoke-RestMethod @splatGetDataParams
            
    }
    catch {           
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex
    
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
        throw "Error querying data from Infor. Error Message: $($errorMessage.AuditErrorMessage)"
    }

    Write-Verbose -verbose "Successfully queried data from Infor. Result count: $($result.Count)"

    return $result
}


# Query departments
try {
    Write-Verbose "Querying departments"

    $DepartmentObjectList = @()
    #fields in url, otherwise this takes long
    $departmentList = Invoke-InforWebRequestList -Url "$queryurl/hcm/soap/classes/HROrganizationUnit/lists/BASEHROrganizationUnitCounts?_limit=1000"
    
    #remove first object which contains no department
    $departmentList = $departmentList[1..($departmentList.Length-1)]

    $departmentList | ForEach-Object {
        $departmentObject = [PSCustomObject]@{}
        $_._fields.PSObject.Properties | ForEach-Object {
            $departmentObject | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value -Force
        }
        $departmentObject | Add-Member -MemberType NoteProperty -Name "ExternalId" -Value $departmentObject.Employee -Force
        $departmentObjectList += $departmentObject
    }

    Write-Verbose -verbose "Successfully queried departments. Result: $($departmentList.Count)"
} catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"      

    throw "Error querying departments. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    Write-Verbose 'Enhancing and exporting department objects to HelloID'

    # Set counter to keep track of actual exported person objects
    $exportedDepartments = 0

    $departmentList  | ForEach-Object {

        #Create department Object
        $DepartmentObject = [PSCustomObject]@{}

        # Enhance the department model
        $DepartmentObject | Add-Member -MemberType NoteProperty -Name "ExternalId" -Value $null -Force
        $DepartmentObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $null -Force

        # Add the provided fields
        $_._fields.PSObject.Properties | ForEach-Object {
            $DepartmentObject | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value -Force
        }
    
        $department = [PSCustomObject]@{
            ExternalId        = $DepartmentObject.HROrganizationUnit
            ShortName         = $DepartmentObject.ShortDescription
            DisplayName       = $DepartmentObject.Description
            #ManagerExternalId = $null
            ParentExternalId  = $DepartmentObject.ParentUnit
        }

        # Sanitize and export the json
        $department = $department | ConvertTo-Json -Depth 10
        $department = $department.Replace("._", "__")

        Write-Output $department

        # Updated counter to keep track of actual exported person objects
        $exportedDepartments++
    }

    Write-Verbose -verbose "Successfully enhanced and exported person objects to HelloID. Result count: $($exportedDepartments)"
    Write-Verbose -verbose "Department import completed"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"     

    throw "Could not enhance and export department objects to HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}