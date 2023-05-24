#####################################################
# HelloID-Conn-Prov-Source-Infor-HCM-Persons
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

Write-Information "Start Person import"

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

# Query persons
try {
    Write-Verbose "Querying persons"

    #fields in url, otherwise this takes long
    $personsList = Invoke-InforWebRequestList -Url "$queryurl/hcm/soap/classes/Employee/lists/_generic?_fields=Employee,Name.FamilyName,Name.FamilyNamePrefix,Name.GivenName,Name.MiddleName,Name.PreferredGivenName,Gender,StartDate,RelationshipToOrganization,MFPJobFunction,MFPJobFunctionId,MFPBusinessUnit,MFPBusinessUnitId,MFPDepartment,MFPDepartmentId,MFPLocation,MFPLocationId,MFPLocationCountry,MFPSupervisorEmployeeNumber,MFPSupervisorName,MFPSupervisorStartDate,LastDateWorked,MappedEmployee,Employee.TerminationDate&_limit=5000"
    
    #remove first object which contains no person
    $personsList = $personsList[1..($personsList.Length-1)]


    Write-Verbose -verbose "Successfully queried persons. Result: $($personsList.Count)"
} catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"      

    throw "Error querying persons. Error Message: $($errorMessage.AuditErrorMessage)"
}


# Query de contracten
try {
    Write-Verbose "Querying contracten"

    $ContractObjectList = @()
    #fields in url, otherwise this takes long
    $contractList = Invoke-InforWebRequestList -Url "$queryurl/hcm/soap/classes/EmployeeContract/lists/EmployeeContracts?_fields=MFPDepartment,EmployeeContractDateRange.BeginDate,EmployeeContractDateRange.EndDate,Employee,EmployeeContract,Status,EmploymentContractType,MFPJobFunction,MFPJobFunctionId,MFPBusinessUnit,MFPBusinessUnitId,MFPDepartmentId,MFPLocation,MFPLocationId,MFPLocationCountry,MFPSupervisorEmployeeNumber,Status&_limit=5000"

    #remove first object which contains no person
    $contractList = $contractList[1..($contractList.Length-1)]

    $contractList | ForEach-Object {
        $ContractObject = [PSCustomObject]@{}
        $_._fields.PSObject.Properties | ForEach-Object {
            $ContractObject | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value -Force
        }
        $ContractObject | Add-Member -MemberType NoteProperty -Name "ExternalId" -Value "$($ContractObject.Employee)$($ContractObject.EmployeeContract)"  -Force
        $ContractObjectList += $ContractObject
    }

    # Group on Medewerker (to match to medewerker)
    $ContractsGrouped = $ContractObjectList | Group-Object Employee -AsHashTable

    Write-Verbose -verbose "Successfully queried contracten. Result: $($contractList.Count)"
} catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"      

    throw "Error querying contracten. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    Write-Verbose 'Enhancing and exporting person objects to HelloID'

    # Set counter to keep track of actual exported person objects
    $exportedPersons = 0

    $personsList  | ForEach-Object {

        #Create person Object
        $PersonObject = [PSCustomObject]@{}

        # Enhance the persons model
        $PersonObject | Add-Member -MemberType NoteProperty -Name "ExternalId" -Value $null -Force
        $PersonObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $null -Force
        $PersonObject | Add-Member -MemberType NoteProperty -Name "Contracts" -Value $null -Force

        # Add the provided fields
        $_._fields.PSObject.Properties | ForEach-Object {
            $PersonObject | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value -Force
        }

        # Set required fields for HelloID
        $PersonObject.ExternalId = $PersonObject.Employee
        $PersonObject.DisplayName = "$($PersonObject."Name.PreferredGivenName") $($PersonObject."Name.FamilyNamePrefix") $($PersonObject."Name.FamilyName")"


        # Create contracts object
        $contractsList = [System.Collections.ArrayList]::new()
        
        # Create fist contract with generated values
        $contracts = $ContractsGrouped[$PersonObject.ExternalId]

        # Format dates
        $Startdate = [datetime]::parseexact($($PersonObject.Startdate), 'yyyyMMdd', $null) 
        $Enddate = ''

        if($($PersonObject.'Employee.TerminationDate') -ne '00000000')
        {
            $Enddate = [datetime]::parseexact($($PersonObject.'Employee.TerminationDate'), 'yyyyMMdd', $null) 
        }

        #To-Do Upper OU en dat soort dingen, dit is de basis
        $employmentObject = [PSCustomObject]@{
            ExternalId          = $PersonObject.Employee + 'X'
            StartDate           = $Startdate
            Enddate             = $Enddate
            TitleName           = $PersonObject.MFPJobFunction
            TitleExternalId     = $PersonObject.MFPJobFunctionId
            DepartmentName      = $PersonObject.MFPDepartment
            DepartmentId        = $PersonObject.MFPDepartmentId
            #ParentExternalId    = $DepartmentObject.ParentUnit
            LocationName        = $PersonObject.MFPLocation
            LocationId          = $PersonObject.MFPLocationId
            ManagerName         = $PersonObject.MFPSupervisorName
            ManagerExternalId   = $PersonObject.MFPSupervisorEmployeeNumber
            Status              = "1"
            ContractSequence    = "1"
            FTE                 = 1
            TypeContract        = $PersonObject.RelationshipToOrganization
        }
        
        [Void]$contractsList.Add($employmentObject)

        #Cleanup calculated contract fields from person object
        
        $PersonObject.PSObject.Properties | ForEach-Object {
                    if($_.Name.startsWith('MFP')){
                        $PersonObject.PSObject.Properties.Remove($_.Name)
                    }     
        }



        if ($null -ne $contracts) {
            foreach ($employment in $contracts) {
                    $employmentObject = [PSCustomObject]@{}

                    # Format dates
                    $Startdate = ''
                    $Enddate = ''

                    # Find corresponding department and title - all those fields are optional so we have to check for values first.

                    if($($employment."EmployeeContractDateRange.BeginDate") -ne '00000000')
                    {
                        $Startdate = [datetime]::parseexact($($employment."EmployeeContractDateRange.BeginDate"), 'yyyyMMdd', $null) 
                    }

                    if($($employment."EmployeeContractDateRange.EndDate") -ne '00000000')
                    {
                        $Enddate = [datetime]::parseexact($($employment."EmployeeContractDateRange.EndDate"), 'yyyyMMdd', $null) 
                    }

                    #Eigenlijk moeten we hier titles en departments even apart ophalen voor de juiste codes, maar betwijfel of we dit gaan gebruiken dus zit er momenteel nog niet in
                    $employmentObject = [PSCustomObject]@{
                        ExternalId          = $employment.Employee + $employment.EmployeeContract
                        StartDate           = $Startdate
                        Enddate             = $Enddate
                        TitleName           = $employment.MFPJobFunction
                        TitleExternalId     = $employment.MFPJobFunctionId
                        DepartmentName      = $employment.MFPDepartment
                        DepartmentId        = $employment.MFPDepartmentId
                        #ParentExternalId    = $DepartmentObject.ParentUnit
                        LocationName        = $employment.MFPLocation
                        LocationId          = $employment.MFPLocationId
                        ManagerName         = ''
                        ManagerExternalId   = $employment.MFPSupervisorEmployeeNumber
                        FTE                 = 0.1
                        Status              = $employment.Status
                        ContractSequence    = [int]$employment.EmployeeContract + 1
                        TypeContract        = $employment.EmploymentContractType
                    }

                    [Void]$contractsList.Add($employmentObject)
                }
            }

        if ($null -ne $contractsList) {
                # This example can be used by the consultant if you want to filter out persons with an empty array as contract
                # *** Please consult with the Tools4ever consultant before enabling this code. ***
                if ($contractsList.Count -eq 0) {
                    # Write-Warning "Excluding person from export: $($_.ExternalId). Reason: Contracts is an empty array"
                    return
                }
                else {
                    $PersonObject.Contracts = $contractsList
                }
        }

        # Sanitize and export the json
        $PersonObject = $PersonObject | ConvertTo-Json -Depth 10
        $PersonObject = $PersonObject.Replace("._", "__")
        $PersonObject = $PersonObject.Replace("Name.", "Name")

        Write-Output $PersonObject

        # Updated counter to keep track of actual exported person objects
        $exportedPersons++
    }

    Write-Verbose -verbose "Successfully enhanced and exported person objects to HelloID. Result count: $($exportedPersons)"
    Write-Verbose -verbose "Person import completed"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"     

    throw "Could not enhance and export person objects to HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}