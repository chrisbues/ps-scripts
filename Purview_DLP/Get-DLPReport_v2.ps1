# Requires -modules ExchangeOnlineManagement
<#
.SYNOPSIS
    Get DLP Policy Hits for a specific policy
.DESCRIPTION
    Gets DLP policy hits for a sepcified DLP policy (or all policies) using the ExchangeOnlineManagement module.
    By default this writes the results to the current directory. Use the -Reportpath option to specify a different path.
.EXAMPLE
    Get-DLPReport -PolicyName 'DLP Policy Name'
.EXAMPLE
    $results = Get-DLPReport -StartDate 10/10/2021 -ReturnResults
.INPUTS
    Policy Name, Start Date and End Date
.OUTPUTS
    If the ReturnResults flag is specified, returns a [System.Collections.Generic.List] of Objects.
#>

# Add a TrimDay method to DateTime
Update-TypeData -TypeName System.DateTime -MemberName TrimDay -MemberType ScriptMethod -Value { [datetime]($this.ticks - ($this.ticks % ((New-TimeSpan -Days 1).ticks)))} -Force

Function Get-DLPReport2 {
    [CmdletBinding(PositionalBinding=$false,DefaultParameterSetName='User')]
    Param (
        # DLP Policy Name
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [string]
        $PolicyName,

        # Start Date. Default is -29 days from now.
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [ValidateScript({[boolean]($_ -as [datetime]) -and [datetime]$_ -ge (get-date).addDays(-30).ToUniversalTime() -and [datetime]$_ -le (Get-date) })]
        [datetime]
        $StartDate,

        # End Date. Default is now.
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [ValidateScript({[boolean]($_ -as [datetime]) -and [datetime]$_ -le (Get-date) -and [datetime]$_ -ge (get-date).addDays(-30).ToUniversalTime() })]
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

    #Import the ExchangeOnlineManagement module.
    try { import-module ExchangeOnlineManagement } catch { Throw 'Unable to import ExchangeOnlineManagement module. Please ensure the ExchangeOnlineManagement module is installed.' }


    # Parameters for Connect-IPPSSession
    $params = @{}
    if ($CertificateThumbPrint) { $params.Add('CertificateThumbprint', $CertificateThumbPrint)}
    if ($AppID) { $params.Add('AppID', $AppID)}
    if ($Organization) { $params.Add('Organization', $Organization)}

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
            Connect-IPPSSession @params
        }
        elseif ($psSessions.where({ $_.State -eq 'Opened' -and $_.ComputerName -like '*.compliance.protection.outlook.com' })) {
            Write-Information "Using existing session."
        }
        else
        {
            Write-Information "Connecting to Compliance Center."
            Connect-IPPSSession @params
        }
    }
    catch {
        Throw "Error connecting to Compliance Center."
    }

    # Get name of tenant. This is stupid, but it works.
    $policy = (Get-PolicyConfig).Id
    $tenant = ($policy.Split('/'))[2]

    Write-Information "Connected to $tenant"


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

    if ($policyname) {
        $reportFullPath = ([String]::Format("DLP Report For Policy {0} in Tenant {1} - {2} to {3} - Generated on {4}.csv", $PolicyName, $tenant, $StartDate.ToString('s'), $EndDate.ToString('s'), (get-date).ToString('s')))
    }
    else {
        $reportFullPath = ([String]::Format("DLP Report For All Policies in Tenant {0} - {1} to {2} - Generated on {3}.csv", $tenant, $StartDate.ToString('s'), $EndDate.ToString('s'), (get-date).ToString('s')))
    }

    $reportFullPath = "$ReportPath\" + [String]::join('_', $reportFullPath.Split([IO.Path]::GetInvalidFileNameChars()))

    # datatable for results
    $dlpResultsDT = [System.Data.DataTable]::new()
    $col = [System.Data.Datacolumn]::new()
    $col.ColumnName = 'ObjectId'
    $col.DataType = [string]
    $col.MaxLength = 900
    $col.AllowDBNull = $false
    [void] $dlpResultsDT.Columns.Add($col)
    [void] $dlpResultsDT.Columns.Add('PSComputerName', [string])
	[void] $dlpResultsDT.Columns.Add('RunspaceId', [string])
	[void] $dlpResultsDT.Columns.Add('PSShowComputerName', [string])
	[void] $dlpResultsDT.Columns.Add('Organization', [string])
	[void] $dlpResultsDT.Columns.Add('Domain', [string])
	[void] $dlpResultsDT.Columns.Add('Date', [datetime])
	[void] $dlpResultsDT.Columns.Add('Title', [string])
	[void] $dlpResultsDT.Columns.Add('Location', [string])
	[void] $dlpResultsDT.Columns.Add('Severity', [string])
	[void] $dlpResultsDT.Columns.Add('Size', [int])
	[void] $dlpResultsDT.Columns.Add('Source', [string])
	[void] $dlpResultsDT.Columns.Add('Actor', [string])
	[void] $dlpResultsDT.Columns.Add('DlpCompliancePolicy', [string])
	[void] $dlpResultsDT.Columns.Add('DlpComplianceRule', [string])
	[void] $dlpResultsDT.Columns.Add('UserAction', [string])
	[void] $dlpResultsDT.Columns.Add('Justification', [string])
	[void] $dlpResultsDT.Columns.Add('SensitiveInformationType', [string])
	[void] $dlpResultsDT.Columns.Add('SensitiveInformationCount', [int])
	[void] $dlpResultsDT.Columns.Add('SensitiveInformationConfidence', [int])
	[void] $dlpResultsDT.Columns.Add('SensitiveInformationConfidenceLevel', [string])
	[void] $dlpResultsDT.Columns.Add('EventType', [string])
	[void] $dlpResultsDT.Columns.Add('Action', [string])
	[void] $dlpResultsDT.Columns.Add('Operation', [string])
	[void] $dlpResultsDT.Columns.Add('LastModifiedTime', [dateTime])
	[void] $dlpResultsDT.Columns.Add('Recipients', [string])
	[void] $dlpResultsDT.Columns.Add('AttachmentNames', [string])
	[void] $dlpResultsDT.Columns.Add('OtherSensitiveTypesDetected', [string])
	[void] $dlpResultsDT.Columns.Add('StartDate', [dateTime])
	[void] $dlpResultsDT.Columns.Add('EndDate', [dateTime])
	[void] $dlpResultsDT.Columns.Add('Index', [int])

    foreach ($range in $ranges) {
        try {
            $page = 1
            Write-Information "Processing Date Range: $($range.startDate.ToShortDateString()) - $($range.endDate.ToShortDateString())"
            do
                {
                    Write-Information "Gathering Results for Page $Page..."

                    try {
                        # Build parameters
                        $params = @{
                            'StartDate' = $range.startDate
                            'EndDate'   = $range.endDate
                            'Page'      = $page
                            'PageSize'  = 5000
                            'EventType' = 'DlpPolicyHits'
                            'ErrorAction' = 'Stop'
                        }
                                                if ($PolicyName) {
                            $params['DlpCompliancePolicy'] = $PolicyName
                        }
                        #$response = Get-DlpDetailReport -DlpCompliancePolicy $policyName -PageSize 5000 -startDate $range.startDate -enddate $range.endDate -page $page -EventType DLPPolicyHits -ErrorAction Stop
                        $response = Get-DlpDetailReport @params
                    }
                    catch [System.Management.Automation.Remoting.PSRemotingTransportException]{

                        # Session expiration. Try to reconnect.
                        if ($_.Exception.Message -like '*failed because the shell was not found on the server*') {
                            Write-Information "Session Expired. Reconnecting..."

                            # Clear sessions and reconnect
                            $psSessions.where({$_.ComputerName -like '*.compliance.protection.outlook.com'}) | Remove-PSSession
                            # Create a new session
                            Connect-IPPSSession

                        }
                    }
                    catch {
                        Throw "Error getting DLP Report."
                    }
                    if ($null -ne $response)
                        {
                            Write-Information "Page $Page - Received $($response.count) results"
                            # Add results to DB

                            # Add results to datatable
                            try {

                                foreach ($item in $response) {
                                    $row = $dlpResultsDT.NewRow()
                                    $row.Item('ObjectId') = [string]$item.ObjectId
                                    $row.Item('PSComputerName') = [string]$item.PSComputerName
                                    $row.Item('RunspaceId') = [string]$item.RunspaceId
                                    $row.Item('PSShowComputerName') = [string]$item.PSShowComputerName
                                    $row.Item('Organization') = [string]$item.Organization
                                    $row.Item('Domain') = [string]$item.Domain
                                    $row.Item('Date') = [datetime]$item.Date
                                    $row.Item('Title') = [string]$item.Title
                                    $row.Item('Location') = [string]$item.Location
                                    $row.Item('Severity') = [string]$item.Severity
                                    $row.Item('Size') = [int]$item.Size
                                    $row.Item('Source') = [string]$item.Source
                                    $row.Item('Actor') = [string]$item.Actor
                                    $row.Item('DlpCompliancePolicy') = [string]$item.DlpCompliancePolicy
                                    $row.Item('DlpComplianceRule') = [string]$item.DlpComplianceRule
                                    $row.Item('UserAction') = [string]$item.UserAction
                                    $row.Item('Justification') = [string]$item.Justification
                                    $row.Item('SensitiveInformationType') = [string]$item.SensitiveInformationType
                                    $row.Item('SensitiveInformationCount') = [int]$item.SensitiveInformationCount
                                    $row.Item('SensitiveInformationConfidence') = [int]$item.SensitiveInformationConfidence
                                    $row.Item('SensitiveInformationConfidenceLevel') = [string]$item.SensitiveInformationConfidenceLevel
                                    $row.Item('EventType') = [string]$item.EventType
                                    $row.Item('Action') = [string]$item.Action
                                    $row.Item('Operation') = [string]$item.Operation
                                    $row.Item('LastModifiedTime') = [datetime]$item.LastModifiedTime
                                    $row.Item('Recipients') = [string]$item.Recipients
                                    $row.Item('AttachmentNames') = [string]$item.AttachmentNames
                                    $row.Item('OtherSensitiveTypesDetected') = [string]$item.OtherSensitiveTypesDetected
                                    $row.Item('StartDate') = [datetime]$range.startDate
                                    $row.Item('EndDate') = [datetime]$range.endDate
                                    $row.Item('Index') = [int]$item.Index
                                    [void] $dlpResultsDT.Rows.Add($row)
                                }

                            }
                            catch {
                                Throw "Error adding results to DB."
                            }

                        }
                        else {
                            Write-Information "Empty result set returned. Moving onto next date range."
                        }

                    $Page++
                } until ($null -eq $response)
        }
        catch {
            Throw "Error getting DLP report"
        }
    }

    # Get Count of records.

    Write-Information "Total Records: $($dlpResultsDT.Rows.Count)"


    # dedupe

    Write-Information "Deduping results"


    try {
        $dedupe = [Linq.Enumerable]::Distinct([System.Data.DataTableExtensions]::AsEnumerable($dlpResultsDT),[System.Data.DataRowComparer]::Default)
        Write-Information "Deduped Records: $($dedupe.rows.Count)"
    }
    catch {
        Throw "Error deduping results"
    }

    # exort to CSV

    try {
        $dedupe | Export-Csv -Path $reportFullPath -NoTypeInformation -Force
    }
    catch {
        Throw "Error exporting results"

    }

    Write-Information "Complete. Report is located at $reportFullPath"

    $InformationPreference = $PreviousInformationPreference

    # return results

    Write-Information "Returning results."

    if ($ReturnResults) {return $dedupe}

}


Function Get-DLPReport2.1 {
    [CmdletBinding(PositionalBinding=$false,DefaultParameterSetName='default')]
    Param (
        # Approach. Determines which cmdlet is used to export the report.
        [Parameter(Mandatory=$true)]
        [ValidateSet('DLP','ActivityExplorer')]
        [string]
        $Approach,

        # DLP Policy Name
        [Parameter(Mandatory=$false)]
        [string]
        $PolicyName,

        # DLP Event Type
        [Parameter(ParameterSetName='DLP', Mandatory=$false)]
        [ValidateSet('DLPActionHits','DLPActionUndo','DLPMessages','DLPPolicyFalsePositive','DLPPolicyHits','DLPPolicyOverride','DLPRuleHits')]
        [string]
        $DLPEventType

        # Activity Explorer Event Type
        [Parameter(ParameterSetName='Activity', Mandatory=$false)]
        [string]

        # Start Date. Default is -29 days from now.
        [Parameter(Mandatory=$false)]
        [ValidateScript({[boolean]($_ -as [datetime]) -and [datetime]$_ -ge (get-date).addDays(-30).ToUniversalTime() -and [datetime]$_ -le (Get-date) })]
        [datetime]
        $StartDate,

        # End Date. Default is now.
        [Parameter(Mandatory=$false)]
        [ValidateScript({[boolean]($_ -as [datetime]) -and [datetime]$_ -le (Get-date) -and [datetime]$_ -ge (get-date).addDays(-30).ToUniversalTime() })]
        [datetime]
        $EndDate,

        # Report Path. Defaults to the current directory.
        [Parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container })]
        [string]
        $ReportPath = (Get-Location).Path,

        # Return a generic list object of the results. For queries with a lot of results, this can consume a tremendous amout of memory.
        [Parameter(Mandatory=$false)]
        [switch]
        $ReturnResults,

        # Close any existing sessions and create a new one.
        [Parameter(Mandatory=$false)]
        [switch]
        $NewSession,

        # Certificate Thumbprint
        [Parameter(ParameterSetName='Certificate')]
        [string]
        $CertificateThumbPrint,

        # Application ID
        [Parameter(ParameterSetName='Certificate')]
        [string]
        $AppID,

        # Organization ID
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [string]
        $Organization

    )

    $PreviousInformationPreference = $InformationPreference
    $InformationPreference = 'Continue'

    #Import the ExchangeOnlineManagement module.
    try { import-module ExchangeOnlineManagement } catch { Throw 'Unable to import ExchangeOnlineManagement module. Please ensure the ExchangeOnlineManagement module is installed.' }


    # Parameters for Connect-IPPSSession
    $params = @{}
    if ($CertificateThumbPrint) { $params.Add('CertificateThumbprint', $CertificateThumbPrint)}
    if ($AppID) { $params.Add('AppID', $AppID)}
    if ($Organization) { $params.Add('Organization', $Organization)}

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
            Connect-IPPSSession @params
        }
        elseif ($psSessions.where({ $_.State -eq 'Opened' -and $_.ComputerName -like '*.compliance.protection.outlook.com' })) {
            Write-Information "Using existing session."
        }
        else
        {
            Write-Information "Connecting to Compliance Center."
            Connect-IPPSSession @params
        }
    }
    catch {
        Throw "Error connecting to Compliance Center."
    }

    # Get name of tenant. This is stupid, but it works.
    $policy = (Get-PolicyConfig).Id
    $tenant = ($policy.Split('/'))[2]

    Write-Information "Connected to $tenant"


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

    if ($policyname) {
        $reportFullPath = ([String]::Format("DLP Report For Policy {0} in Tenant {1} - {2} to {3} - Generated on {4}.csv", $PolicyName, $tenant, $StartDate.ToString('s'), $EndDate.ToString('s'), (get-date).ToString('s')))
    }
    else {
        $reportFullPath = ([String]::Format("DLP Report For All Policies in Tenant {0} - {1} to {2} - Generated on {3}.csv", $tenant, $StartDate.ToString('s'), $EndDate.ToString('s'), (get-date).ToString('s')))
    }

    $reportFullPath = "$ReportPath\" + [String]::join('_', $reportFullPath.Split([IO.Path]::GetInvalidFileNameChars()))

    # datatable for results
    $dlpResultsDT = [System.Data.DataTable]::new()
    $col = [System.Data.Datacolumn]::new()
    $col.ColumnName = 'ObjectId'
    $col.DataType = [string]
    $col.MaxLength = 900
    $col.AllowDBNull = $false
    [void] $dlpResultsDT.Columns.Add($col)
    [void] $dlpResultsDT.Columns.Add('PSComputerName', [string])
	[void] $dlpResultsDT.Columns.Add('RunspaceId', [string])
	[void] $dlpResultsDT.Columns.Add('PSShowComputerName', [string])
	[void] $dlpResultsDT.Columns.Add('Organization', [string])
	[void] $dlpResultsDT.Columns.Add('Domain', [string])
	[void] $dlpResultsDT.Columns.Add('Date', [datetime])
	[void] $dlpResultsDT.Columns.Add('Title', [string])
	[void] $dlpResultsDT.Columns.Add('Location', [string])
	[void] $dlpResultsDT.Columns.Add('Severity', [string])
	[void] $dlpResultsDT.Columns.Add('Size', [int])
	[void] $dlpResultsDT.Columns.Add('Source', [string])
	[void] $dlpResultsDT.Columns.Add('Actor', [string])
	[void] $dlpResultsDT.Columns.Add('DlpCompliancePolicy', [string])
	[void] $dlpResultsDT.Columns.Add('DlpComplianceRule', [string])
	[void] $dlpResultsDT.Columns.Add('UserAction', [string])
	[void] $dlpResultsDT.Columns.Add('Justification', [string])
	[void] $dlpResultsDT.Columns.Add('SensitiveInformationType', [string])
	[void] $dlpResultsDT.Columns.Add('SensitiveInformationCount', [int])
	[void] $dlpResultsDT.Columns.Add('SensitiveInformationConfidence', [int])
	[void] $dlpResultsDT.Columns.Add('SensitiveInformationConfidenceLevel', [string])
	[void] $dlpResultsDT.Columns.Add('EventType', [string])
	[void] $dlpResultsDT.Columns.Add('Action', [string])
	[void] $dlpResultsDT.Columns.Add('Operation', [string])
	[void] $dlpResultsDT.Columns.Add('LastModifiedTime', [dateTime])
	[void] $dlpResultsDT.Columns.Add('Recipients', [string])
	[void] $dlpResultsDT.Columns.Add('AttachmentNames', [string])
	[void] $dlpResultsDT.Columns.Add('OtherSensitiveTypesDetected', [string])
	[void] $dlpResultsDT.Columns.Add('StartDate', [dateTime])
	[void] $dlpResultsDT.Columns.Add('EndDate', [dateTime])
	[void] $dlpResultsDT.Columns.Add('Index', [int])

    foreach ($range in $ranges) {
        try {
            $page = 1
            Write-Information "Processing Date Range: $($range.startDate.ToShortDateString()) - $($range.endDate.ToShortDateString())"
            do
                {
                    Write-Information "Gathering Results for Page $Page..."

                    try {
                        # Build parameters
                        $params = @{
                            'StartDate' = $range.startDate
                            'EndDate'   = $range.endDate
                            'Page'      = $page
                            'PageSize'  = 5000
                            'EventType' = 'DlpPolicyHits'
                            'ErrorAction' = 'Stop'
                        }
                                                if ($PolicyName) {
                            $params['DlpCompliancePolicy'] = $PolicyName
                        }
                        #$response = Get-DlpDetailReport -DlpCompliancePolicy $policyName -PageSize 5000 -startDate $range.startDate -enddate $range.endDate -page $page -EventType DLPPolicyHits -ErrorAction Stop
                        $response = Get-DlpDetailReport @params
                    }
                    catch [System.Management.Automation.Remoting.PSRemotingTransportException]{

                        # Session expiration. Try to reconnect.
                        if ($_.Exception.Message -like '*failed because the shell was not found on the server*') {
                            Write-Information "Session Expired. Reconnecting..."

                            # Clear sessions and reconnect
                            $psSessions.where({$_.ComputerName -like '*.compliance.protection.outlook.com'}) | Remove-PSSession
                            # Create a new session
                            Connect-IPPSSession

                        }
                    }
                    catch {
                        Throw "Error getting DLP Report."
                    }
                    if ($null -ne $response)
                        {
                            Write-Information "Page $Page - Received $($response.count) results"
                            # Add results to DB

                            # Add results to datatable
                            try {

                                foreach ($item in $response) {
                                    $row = $dlpResultsDT.NewRow()
                                    $row.Item('ObjectId') = [string]$item.ObjectId
                                    $row.Item('PSComputerName') = [string]$item.PSComputerName
                                    $row.Item('RunspaceId') = [string]$item.RunspaceId
                                    $row.Item('PSShowComputerName') = [string]$item.PSShowComputerName
                                    $row.Item('Organization') = [string]$item.Organization
                                    $row.Item('Domain') = [string]$item.Domain
                                    $row.Item('Date') = [datetime]$item.Date
                                    $row.Item('Title') = [string]$item.Title
                                    $row.Item('Location') = [string]$item.Location
                                    $row.Item('Severity') = [string]$item.Severity
                                    $row.Item('Size') = [int]$item.Size
                                    $row.Item('Source') = [string]$item.Source
                                    $row.Item('Actor') = [string]$item.Actor
                                    $row.Item('DlpCompliancePolicy') = [string]$item.DlpCompliancePolicy
                                    $row.Item('DlpComplianceRule') = [string]$item.DlpComplianceRule
                                    $row.Item('UserAction') = [string]$item.UserAction
                                    $row.Item('Justification') = [string]$item.Justification
                                    $row.Item('SensitiveInformationType') = [string]$item.SensitiveInformationType
                                    $row.Item('SensitiveInformationCount') = [int]$item.SensitiveInformationCount
                                    $row.Item('SensitiveInformationConfidence') = [int]$item.SensitiveInformationConfidence
                                    $row.Item('SensitiveInformationConfidenceLevel') = [string]$item.SensitiveInformationConfidenceLevel
                                    $row.Item('EventType') = [string]$item.EventType
                                    $row.Item('Action') = [string]$item.Action
                                    $row.Item('Operation') = [string]$item.Operation
                                    $row.Item('LastModifiedTime') = [datetime]$item.LastModifiedTime
                                    $row.Item('Recipients') = [string]$item.Recipients
                                    $row.Item('AttachmentNames') = [string]$item.AttachmentNames
                                    $row.Item('OtherSensitiveTypesDetected') = [string]$item.OtherSensitiveTypesDetected
                                    $row.Item('StartDate') = [datetime]$range.startDate
                                    $row.Item('EndDate') = [datetime]$range.endDate
                                    $row.Item('Index') = [int]$item.Index
                                    [void] $dlpResultsDT.Rows.Add($row)
                                }

                            }
                            catch {
                                Throw "Error adding results to DB."
                            }

                        }
                        else {
                            Write-Information "Empty result set returned. Moving onto next date range."
                        }

                    $Page++
                } until ($null -eq $response)
        }
        catch {
            Throw "Error getting DLP report"
        }
    }

    # Get Count of records.

    Write-Information "Total Records: $($dlpResultsDT.Rows.Count)"


    # dedupe

    Write-Information "Deduping results"


    try {
        $dedupe = [Linq.Enumerable]::Distinct([System.Data.DataTableExtensions]::AsEnumerable($dlpResultsDT),[System.Data.DataRowComparer]::Default)
        Write-Information "Deduped Records: $($dedupe.rows.Count)"
    }
    catch {
        Throw "Error deduping results"
    }

    # exort to CSV

    try {
        $dedupe | Export-Csv -Path $reportFullPath -NoTypeInformation -Force
    }
    catch {
        Throw "Error exporting results"

    }

    Write-Information "Complete. Report is located at $reportFullPath"

    $InformationPreference = $PreviousInformationPreference

    # return results

    Write-Information "Returning results."

    if ($ReturnResults) {return $dedupe}

}