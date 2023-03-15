# Requires -modules MSAL.PS
<#
.SYNOPSIS
    Get Defender for Endpoint Enrolled Machines
.DESCRIPTION
    Get Defender for Endpoint enrolled machines using the DfE API.
    By default this writes the results to the current directory. Use the -Reportpath option to specify a different path.
    For application permissions, requires WindowsDefenderATP Machine.Read.
    For delegated permissions, requires WindowsDefenderATP Machine.Read.All.
.EXAMPLE
    Get-DefenderEndpointEnrolledMachines
.EXAMPLE
    $results = Get-DefenderEndpointEnrolledMachines ReturnResults
.INPUTS
    None. You cannot pipe objects to Get-DefenderEnrolledMachines.
.OUTPUTS
    If the ReturnResults flag is specified, returns a [System.Data.DataTable].
#>

# Add a TrimDay method to DateTime
Update-TypeData -TypeName System.DateTime -MemberName TrimDay -MemberType ScriptMethod -Value { [datetime]($this.ticks - ($this.ticks % ((New-TimeSpan -Days 1).ticks)))} -Force

Function Get-DefenderEndpointEnrolledMachines {
    [CmdletBinding(PositionalBinding=$false,DefaultParameterSetName='User')]
    Param (

        # Tenant ID
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [Parameter(Mandatory=$true, ParameterSetName='Secret')]
        [Parameter(Mandatory=$true, ParameterSetName='User')]
        # ID of the tenant
        [string] $TenantID,

        # Client ID
        [Parameter(Mandatory=$true, ParameterSetName='User')]
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [Parameter(Mandatory=$true, ParameterSetName='Secret')]
        # Client (APplication) ID of the app registration in AAD
        [string] $ClientID,

        # Secret
        [Parameter(Mandatory=$true, ParameterSetName='Secret')]
        # Client secret
        [string] $ClientSecret,

        # Certificate Thumbprint
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        # Certificate thumprint. Must be a valid certificate in the CurrentUser\My store.
        [string] $CertificateThumbPrint,

        # Filter
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [Parameter(ParameterSetName='Secret', Mandatory=$false)]
        # DataTable filter expression to filter results prior to returning. See https://docs.microsoft.com/en-us/dotnet/api/system.data.datatable.select?view=net-7.0
        [string] $Filter,

        # Report path
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [Parameter(ParameterSetName='Secret', Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container })]
        # Report Path. Defaults to the current directory if not specified.
        [string] $ReportPath = (Get-Location).Path,

        # Skip writing report
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [Parameter(ParameterSetName='Secret', Mandatory=$false)]
        # Skip writing the report to disk. Useful if you only want the datatable.
        [switch] $SkipReport,

        # Return datatable
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        [Parameter(ParameterSetName='Certificate', Mandatory=$false)]
        [Parameter(ParameterSetName='Secret', Mandatory=$false)]
        # Return a datatable object of the results.
        [switch] $ReturnResults,

        # DLP endpoint switch
        [Parameter(ParameterSetName='User', Mandatory=$false)]
        # Use the machines/dlp endpoint when used with a user credential. Requires delegated application permissions of Machine.Read.All.
        [switch] $UseDLPEndpoint

    )

    $PreviousInformationPreference = $InformationPreference
    $InformationPreference = 'Continue'

    # Get token

    $scopes = 'https://api.securitycenter.microsoft.com/.default'


    switch ($PsCmdlet.ParameterSetName) {
        # User
        "User" {
            try {
                $token = Get-MsalToken -Scopes $scopes -ClientId $ClientID -TenantId $TenantID -Interactive
                Write-Verbose $token
            }
            catch {
                Write-Error "Unable to get token. $($_.Exception.Message)" -ErrorAction Stop
            }
        }

        # Certificate
        "Certificate" {
            # verify certificate is present in user cert store
            try {
                $cert = Get-ChildItem -Path Cert:\CurrentUser\My -Recurse | Where-Object {$_.Thumbprint -eq $CertificateThumbPrint}
                $token = Get-MsalToken -Scopes $scopes -ClientId $ClientID -TenantId $TenantID -ClientCertificate $cert
                Write-Verbose $token

            }
            catch {
                Write-Error "Unable to find certificate with thumbprint $CertificateThumbPrint in the user certificate store." -ErrorAction Stop
            }
        }

        # Secret
        "Secret" {
            try {
                $token = Get-MsalToken -Scopes $scopes -ClientId $ClientID -TenantId $TenantID -ClientSecret $ClientSecret 
                Write-Verbose $token
            }
            catch {
                Write-Error "Unable to get token. $($_.Exception.Message)" -ErrorAction Stop
            }
        }
    }

    # List to hold results
    $results = [System.Collections.Generic.List[object]]::new()

    # CSV Name
    $reportName = ([String]::Format("DLP Enrolled Report in Tenant {0} - Generated on {1}.csv", $tenantID,  (get-date).ToString('s')))
    $reportFullPath = "$ReportPath\" + [String]::join('_', $reportName.Split([IO.Path]::GetInvalidFileNameChars()))

    # Build Datatables

    if ($UseDLPEndpoint) {
        # DT for results
        $resultsDT = [System.Data.DataTable]::new()
        $col = [System.Data.Datacolumn]::new()
        $col.ColumnName = 'id'
        $col.DataType = [string]
        $col.MaxLength = 900
        $col.AllowDBNull = $false
        [void] $resultsDT.Columns.Add($col)
        [void] $resultsDT.Columns.Add('computerDnsName', [string])
        [void] $resultsDT.Columns.Add('healthStatus', [string])
        [void] $resultsDT.Columns.Add('configStatus', [string])
        [void] $resultsDT.Columns.Add('lastSeen', [datetime])
        [void] $resultsDT.Columns.Add('osPlatform', [string])
        [void] $resultsDT.Columns.Add('osVersion', [string])

    }
    else {
        # DT for results
        $resultsDT = [System.Data.DataTable]::new()
        $col = [System.Data.Datacolumn]::new()
        $col.ColumnName = 'id'
        $col.DataType = [string]
        $col.MaxLength = 900
        $col.AllowDBNull = $false
        [void] $resultsDT.Columns.Add($col)
        [void] $resultsDT.Columns.Add('computerDnsName', [string])
        [void] $resultsDT.Columns.Add('firstSeen', [dateTime])
        [void] $resultsDT.Columns.Add('lastSeen', [datetime])
        [void] $resultsDT.Columns.Add('osPlatform', [string])
        [void] $resultsDT.Columns.Add('osVersion', [string])
        [void] $resultsDT.Columns.Add('osProcessor', [string])
        [void] $resultsDT.Columns.Add('version', [string])
        [void] $resultsDT.Columns.Add('lastIpAddress', [string])
        [void] $resultsDT.Columns.Add('lastExternalIpAddress', [string])
        [void] $resultsDT.Columns.Add('agentVersion', [string])
        [void] $resultsDT.Columns.Add('osBuild', [string])
        [void] $resultsDT.Columns.Add('healthStatus', [string])
        [void] $resultsDT.Columns.Add('deviceValue', [string])
        [void] $resultsDT.Columns.Add('isAadJoined', [bool])
        [void] $resultsDT.Columns.Add('aadDeviceId', [string])
        [void] $resultsDT.Columns.Add('defenderAvStatus', [string])
        [void] $resultsDT.Columns.Add('onboardingStatus', [string])
        [void] $resultsDT.Columns.Add('managedBy', [string])
        [void] $resultsDT.Columns.Add('managedByStatus', [string])
    }

    # Get machines

    # Make the header
    $header = @{
        'Authorization' = "Bearer " + $token.accessToken
    }

    if ($PsCmdlet.ParameterSetName -eq 'User' -and $UseDLPEndpoint) {
        $uri = "https://api.securitycenter.microsoft.com/api/machines/dlp"
    }
    else {
        $uri = $uri = "https://api-us.securitycenter.windows.com/api/machines?`$filter=healthStatus in ('Active', 'Inactive') and onboardingStatus eq 'Onboarded'"
    }

    # Requests

    do {

        # Make the header
        $header = @{
            'Authorization' = "Bearer " + $token.accessToken
        }


        try {
            $response = Invoke-RestMethod -Headers $header -Uri $uri -Method Get -RetryIntervalSec 5 -MaximumRetryCount 0
        }
        catch {
            Write-Error "Caught $($_.Exception.Response.StatusCode): $($_.ErrorDetails)" -ErrorAction Stop
        }

        switch ($response) {
            # more than one record returned.
            ( { $PSItem.value.length -gt 0 }) {
                # Add the response.value array to the results
                [void]$results.addrange($response.value)
            }

            # empty result returned
            ( { $PSItem.psobject.Properties.name -contains 'value' -and $PSItem.value.length -eq 0 }) {
                # do nothing
            }

            default {
                # singular result
                [void]$results.add($response)

            }

        }

        # If we have another url to call, do it
        if ($response.'@odata.nextlink' -or $response.'odata.nextlink') {
            # public api
            if ($response.'@odata.nextlink') {
                $uri = $response.'@odata.nextlink'
                $nextLink = $true
            }
        }
        else { $nextLink = $false }

        #}
    } until ($nextLink -eq $false)

 
    # Build datatable

    if ($UseDLPEndpoint) {
        foreach ($machine in $results) {
            $row = $resultsDT.NewRow()
            $row['id'] = $machine.id
            $row['computerDnsName'] = $machine.computerDnsName
            $row['healthStatus'] = $machine.healthStatus
            $row['configStatus'] = $machine.configStatus
            $row['lastSeen'] = $machine.lastSeen
            $row['osPlatform'] = $machine.osPlatform
            $row['osVersion'] = $machine.Version
            $resultsDT.Rows.Add($row)
        }
    }
    else {
        foreach ($machine in $results) {
            $row = $resultsDT.NewRow()
            $row['id'] = $machine.id
            $row['computerDnsName'] = $machine.computerDnsName
            $row['firstSeen'] = $machine.firstSeen
            $row['lastSeen'] = $machine.lastSeen
            $row['osPlatform'] = $machine.osPlatform
            $row['osVersion'] = $machine.osVersion
            $row['osProcessor'] = $machine.osProcessor
            $row['version'] = $machine.version
            $row['lastIpAddress'] = $machine.lastIpAddress
            $row['lastExternalIpAddress'] = $machine.lastExternalIpAddress
            $row['agentVersion'] = $machine.agentVersion
            $row['osBuild'] = $machine.osBuild
            $row['healthStatus'] = $machine.healthStatus
            $row['deviceValue'] = $machine.deviceValue
            $row['isAadJoined'] = $machine.isAadJoined
            $row['aadDeviceId'] = $machine.aadDeviceId
            $row['defenderAvStatus'] = $machine.defenderAvStatus
            $row['onboardingStatus'] = $machine.onboardingStatus
            $row['managedBy'] = $machine.managedBy
            $row['managedByStatus'] = $machine.managedByStatus
            $resultsDT.Rows.Add($row)
        }
    }


    # export to CSV

    if (!($SkipReport)) {
        try {
            $resultsDT | Export-Csv -Path $reportFullPath -NoTypeInformation -Force
            Write-Information "Complete. Report is located at $reportFullPath"
        }
        catch {
            Write-Error "Caught $($_.Exception.Message)" -ErrorAction Stop
        }
    }

    # return results

    if ($ReturnResults) {
        Write-Information "Returning results."
        return @( ,$resultsDT)
    }

    $InformationPreference = $PreviousInformationPreference

}
