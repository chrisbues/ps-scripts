# Requires -modules @{ModuleName=ExchangeOnlineManagement, ModuleVersion=3.0.0}
<#
.SYNOPSIS
    Get Purview Activity Explorer DLP reports
.DESCRIPTION
    Get Purview Activity Explorer DLP reports using the ExchangeOnlineManagement module.
    By default this writes the results for the last 30 days to the current directory. Use the -Reportpath option to specify a different path.
.EXAMPLE
    Get-ActivityExplorerReport
.EXAMPLE
    $results = Get-ActivityExplorerReport -StartDate 10/10/2021 -ReturnResults
.INPUTS
    None. You cannot pipe objects to Get-ActivityExplorerReport.
.OUTPUTS
    If the ReturnResults flag is specified, returns a [System.Data.DataTable].
#>

# Add a TrimDay method to DateTime
Update-TypeData -TypeName System.DateTime -MemberName TrimDay -MemberType ScriptMethod -Value { [datetime]($this.ticks - ($this.ticks % ((New-TimeSpan -Days 1).ticks)))} -Force

Function Get-ActivityExplorerReport {
    [CmdletBinding(PositionalBinding=$false,DefaultParameterSetName='User')]
    Param (
        <# Using Filter 1 for Activity for now
        # Filter 1
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [array]
        $Filter1,
        #>
        # Filter 2
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [array]
        $Filter2,

        # Filter 3
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [array]
        $Filter3,

        # Filter 4
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [array]
        $Filter4,

        # Filter 5
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [array]
        $Filter5,

        # Start Date. Default is -29 days from now.
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [ValidateScript({[boolean]($_ -as [datetime]) -and [datetime]$_ -ge (get-date).addDays(-30).ToUniversalTime() -and [datetime]$_ -le (Get-date) }, ErrorMessage="{0} must be between 30 days ago and now.")]
        [datetime]
        $StartDate,

        # End Date. Default is now.
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [ValidateScript({[boolean]($_ -as [datetime]) -and [datetime]$_ -le (Get-date) -and [datetime]$_ -ge (get-date).addDays(-30).ToUniversalTime() },ErrorMessage="{0} must be between 30 days ago and now.")]
        [datetime]
        $EndDate,

        # Report Path. Defaults to the current directory.
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container })]
        [string]
        $ReportPath = (Get-Location).Path,

        # Return a generic list object of the results. For queries with a lot of results, this can consume a tremendous amout of memory.
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [switch]
        $ReturnResults,

        # Close any existing sessions and create a new one.
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [switch]
        $NewSession,

        # Certificate Thumbprint
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [string]
        $CertificateThumbPrint,

        # Application ID
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [string]
        $AppID,

        # Organization ID
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [string]
        $Organization

    )

    $PreviousInformationPreference = $InformationPreference
    $InformationPreference = 'Continue'

    # Connect to the tenant

    # Parameters for Connect-IPPS
    $connectexportParams = @{}

    # Cert-based auth
    if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
        $connectexportParams.add('CertificateThumbPrint', $CertificateThumbPrint)
        $connectexportParams.add('AppId', $AppID)
        $connectexportParams.add('Organization', $Organization)
    }

    # Force new session
    if ($NewSession) {
        $connectexportParams.add('NewSession', $true)
    }

    # Connect
    Connect-IPPS @connectexportParams

    # Get name of tenant. This is stupid, but it works.
    $policy = (Get-PolicyConfig).Id
    $tenant = ($policy.Split('/'))[2]

    Write-Information "Connected to $tenant"

    # Get SIT Types
    $sitTypes = Get-DlpSensitiveInformationType

    $sitTypesDT = [System.Data.DataTable]::new()
    $col = [System.Data.Datacolumn]::new()
    $col.ColumnName = 'Id'
    $col.DataType = [string]
    $col.MaxLength = 900
    $col.AllowDBNull = $false
    [void] $sitTypesDT.Columns.Add($col)
    [void] $sitTypesDT.Columns.Add('Name', [string])
    [void] $sitTypesDT.Columns.Add('Publisher', [string])

    # Add SIT Types to DataTable
    foreach ($sitType in $sitTypes) {
        $row = $sitTypesDT.NewRow()
        $row['Id'] = $sitType.Id
        $row['Name'] = $sitType.Name
        $row['Publisher'] = $sitType.Publisher
        [void] $sitTypesDT.Rows.Add($row)
    }

    # Get DLP Policies
    $dlpPolicies = Get-DlpCompliancePolicy

    $dlpPoliciesDT = [System.Data.DataTable]::new()
    $col = [System.Data.Datacolumn]::new()
    $col.ColumnName = 'Id' #Guid or ExchangeObjectId
    $col.DataType = [string]
    $col.MaxLength = 900
    $col.AllowDBNull = $false
    [void] $dlpPoliciesDT.Columns.Add($col)
    [void] $dlpPoliciesDT.Columns.Add('Name', [string])

    # Add the DLP Policies to the DataTable
    foreach ($dlpPolicy in $dlpPolicies) {
        $row = $dlpPoliciesDT.NewRow()
        $row['Id'] = $dlpPolicy.Guid
        $row['Name'] = $dlpPolicy.Name
        [void] $dlpPoliciesDT.Rows.Add($row)
    }

    # Date Ranges
    $ranges = $null
    $ranges = [System.Collections.Generic.List[hashtable]]::new()

    # Build Date Danges
    if ($startDate) {
        $startDate = $startDate.ToUniversalTime().TrimDay()
    }
    else {
        $startDate = (get-date).addDays(-29).ToUniversalTime().TrimDay()
    }

    if ($endDate) {
        $endDate = $endDate.ToUniversalTime().TrimDay()
    }
    else {
        $endDate = (get-date).ToUniversalTime().TrimDay()
    }



    # Build Range Table. Chunk into days.
    $ranges = $null
    $ranges = [System.Collections.Generic.List[hashtable]]::new()


    $stepBegin = $startDate

    do {
        $stepEnd = $stepBegin.AddDays(1)
        Write-Debug "StartDate $stepBegin - EndDate $stepEnd"
        [void]$ranges.Add(@{
                'startDate' = $stepBegin
                'endDate'   = $stepEnd
            })
        $stepBegin = $stepEnd
    } until ($stepEnd -ge $endDate)

    # CSV Name
    $reportFullPath = ([String]::Format("Activity Explorer Report in Tenant {0} - {1} to {2} - Generated on {3}.csv", $tenant, $StartDate.ToString('s'), $EndDate.ToString('s'), (get-date).ToString('s')))

    $reportFullPath = "$ReportPath\" + [String]::join('_', $reportFullPath.Split([IO.Path]::GetInvalidFileNameChars()))


    # Range for results
    $results = [System.Collections.Generic.List[Object]]::new()

    # DT for results
    $resultsDT = [System.Data.DataTable]::new()
    $col = [System.Data.Datacolumn]::new()
    $col.ColumnName = 'RecordIdentity'
    $col.DataType = [string]
    $col.MaxLength = 900
    $col.AllowDBNull = $false
    [void] $resultsDT.Columns.Add($col)
    [void] $resultsDT.Columns.Add('Activity', [string])
    [void] $resultsDT.Columns.Add('Item', [string])
    [void] $resultsDT.Columns.Add('Date', [datetime])
    [void] $resultsDT.Columns.Add('User', [string])
    [void] $resultsDT.Columns.Add('Workload', [string])
    [void] $resultsDT.Columns.Add('Filesize', [int])
    [void] $resultsDT.Columns.Add('SITId', [string])
    [void] $resultsDT.Columns.Add('SITName', [string])
    [void] $resultsDT.Columns.Add('Low', [int])
    [void] $resultsDT.Columns.Add('Medium', [int])
    [void] $resultsDT.Columns.Add('High', [int])
    [void] $resultsDT.Columns.Add('ClassifierType', [string])
    [void] $resultsDT.Columns.Add('Sender', [string])
    [void] $resultsDT.Columns.Add('Receivers', [string])
    [void] $resultsDT.Columns.Add('PolicyId', [string])
    [void] $resultsDT.Columns.Add('PolicyName', [string])


    foreach ($range in $ranges) {
        try {
            Write-Information "Processing Date Range: $($range.startDate.ToShortDateString()) - $($range.endDate.ToShortDateString())"
            # Build parameters
            $exportParams = @{}
            $exportParams['StartTime'] = $range.startDate
            $exportParams['EndTime']  = $range.endDate
            $exportParams['PageSize']  = 5000
            $exportParams['Filter1'] = @('Activity','DLPRuleMatch')
            $exportParams['ErrorAction'] = 'Stop'
            $exportParams['OutputFormat'] = 'JSON'
            if ($Filter2) { $exportParams['Filter2'] = $Filter2 }
            if ($Filter3) { $exportParams['Filter3'] = $Filter3 }
            if ($Filter4) { $exportParams['Filter4'] = $Filter4 }
            if ($Filter5) { $exportParams['Filter5'] = $Filter5 }

            do
                {
                    try {


                        $response = Export-ActivityExplorerData @exportParams
                    }
                    catch [System.Management.Automation.Remoting.PSRemotingTransportException]{

                        # Session expiration. Try to reconnect.
                        if ($_.Exception.Message -like '*failed because the shell was not found on the server*') {
                            Write-Information "Session Expired. Reconnecting..."

                            # Create a new session
                            $connectexportParams['NewSession'] = $true
                            Connect-IPPS @connectexportParams

                        }
                    }
                    catch {
                        Throw $_
                    }

                    # Determine if we have results
                    if ($response.TotalResultCount -gt 0)
                        {
                            Write-Information "Received $($response.RecordCount) out of $($response.TotalResultCount) records."
                            # Add results to DT
                            foreach ($record in $($response.ResultData | ConvertFrom-Json -Depth 20)) {
                                $results.Add($record)

                                # DT
                                # Loop through each unit SIT

                                foreach ($item in $record.SensitiveInfoTypeBucketsData) {
                                    $row = $resultsDT.NewRow()
                                    $row['RecordIdentity'] = $record.RecordIdentity
                                    $row['Activity'] = if ([string]::IsNullOrEmpty($record.Activity)) { [DBNull]::Value } else { $record.Activity }
                                    $row['Item'] =  if ([string]::IsNullOrEmpty($record.FilePath)) { [DBNull]::Value } else { $record.FilePath }
                                    $row['Date'] = $record.Happened
                                    $row['User'] = if ([string]::IsNullOrEmpty($record.User)) { [DBNull]::Value } else { $record.User }
                                    $row['Workload'] = if ([string]::IsNullOrEmpty($record.Workload)) { [DBNull]::Value } else { $record.Workload }
                                    $row['Filesize'] = if ([string]::IsNullOrEmpty($record.Filesize)) { [DBNull]::Value } else { $record.Filesize }
                                    $row['SITId'] =  if ([string]::IsNullOrEmpty($item.Id)) { [DBNull]::Value } else { $item.Id }
                                    $row['SITName'] = [DBNull]::Value
                                    $row['Low'] = if ([string]::IsNullOrEmpty($item.Low)) { [DBNull]::Value } else { $item.Low }
                                    $row['Medium'] = if ([string]::IsNullOrEmpty($item.Medium)) { [DBNull]::Value } else { $item.Medium }
                                    $row['High'] = if ([string]::IsNullOrEmpty($item.High)) { [DBNull]::Value } else { $item.High }
                                    $row['ClassifierType'] = if ([string]::IsNullOrEmpty($item.ClassifierType)) { [DBNull]::Value } else { $item.ClassifierType }
                                    $row['Sender'] = if ([string]::IsNullOrEmpty($record.EmailInfo.Sender)) { [DBNull]::Value } else { $record.EmailInfo.Sender }
                                    $row['Receivers'] =  if ([string]::IsNullOrEmpty($record.EmailInfo.Receivers)) { [DBNull]::Value } else { $( $record.EmailInfo.Receivers | Join-String -Separator ',' ) }
                                    $row['PolicyId'] = $record.PolicyMatchInfo.PolicyId
                                    $row['PolicyName'] = [DBNull]::Value
                                    $resultsDT.Rows.Add($row)
                                }
                        }
                    }
                    else {
                        Write-Information "Empty result set returned. Moving onto next date range."
                    }

                    if ($response.LastPage -eq $false) {
                        $exportParams['PageCookie'] = $response.watermark
                    }

                } while ($response.LastPage -ne $true)
        }
        catch {
            Throw $_
        }
    }



    # Resolve IDs
    # SIT Names

    Write-Information "Resolving SIT Names"
    foreach ($sit in $sitTypesDT) {
        $search = $resultsDT.Select("SITId = '$($sit.Id)'")
        foreach ($row in $search) {
            $row['SITName'] = $sit.Name
        }
    }


    Write-Information "Resolving Policy Names"
    # Policy Names
    foreach ($policy in $dlpPoliciesDT) {
        $search = $resultsDT.Select("PolicyId = '$($policy.Id)'")
        foreach ($row in $search) {
            $row['PolicyName'] = $policy.Name
        }
    }

    $resultsDT.AcceptChanges()

    # exort to CSV

    try {
        $resultsDT | Export-Csv -Path $reportFullPath -NoTypeInformation -Force
    }
    catch {
        Throw "Error exporting results"

    }

    Write-Information "Complete. Report is located at $reportFullPath"

    # return results

    if ($ReturnResults) {
        Write-Information "Returning results."
        return @( ,$resultsDT)
    }

    $InformationPreference = $PreviousInformationPreference

}

# Helper Functions

Function Connect-IPPS {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbPrint,
        [Parameter(Mandatory=$false)]
        [string]$AppID,
        [Parameter(Mandatory=$false)]
        [string]$Organization,
        [Parameter(Mandatory=$false)]
        [switch]$NewSession

    )
    #Import the ExchangeOnlineManagement module.
    try { import-module ExchangeOnlineManagement } catch { Throw 'Unable to import ExchangeOnlineManagement module. Please ensure the ExchangeOnlineManagement module is installed.' }


    # Parameters for Connect-IPPSSession
    $exportParams = @{}
    if ($CertificateThumbPrint) { $exportParams.Add('CertificateThumbprint', $CertificateThumbPrint)}
    if ($AppID) { $exportParams.Add('AppID', $AppID)}
    if ($Organization) { $exportParams.Add('Organization', $Organization)}

    $exportParams.Add('WarningAction', 'SilentlyContinue')

    # Clear any existing sessions if the -NewSession flag is specified.
    if ($NewSession) {
        get-pssession | ? {$_.ComputerName -like '*.compliance.protection.outlook.com'} | Remove-PSSession
    }

    # Get sessions
    $psSessions = get-psSession

    try {
        if (!($psSessions.where({ $_.State -eq 'Opened' -and $_.ComputerName -like '*.compliance.protection.outlook.com' }))) {
            # Clean up any old sessions
            $psSessions.where({$_.ComputerName -like '*.compliance.protection.outlook.com'}) | Remove-PSSession

            # Create a new session
            Connect-IPPSSession @exportParams
        }
        elseif ($psSessions.where({ $_.State -eq 'Opened' -and $_.ComputerName -like '*.compliance.protection.outlook.com' })) {
            Write-Information "Using existing session."
        }
        else
        {
            Write-Information "Connecting to Compliance Center."
            Connect-IPPSSession @exportParams
        }
    }
    catch {
        Throw "Error connecting to Compliance Center."
    }
}
