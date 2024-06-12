<#
.DESCRIPTION Uses the Graph.Powershell SDK and ImportExcel module to generate a report of conditional access policies in a tenant.

.SYNOPSIS
Uses the Graph SDK to pull all policies and service principals in a tenant. It then parses those policies, resolving users and groups to identitfy included and excludes users/groups from each CA.

This script will generate a Excel file in the current directory named "Conditional Access policy Design Report Tenant Display Name yyyy-MM-dd.xlsx".
By default this writes the results to the current directory. Use the -Reportpath option to specify a different path.

When first you will need login via devicelogin against the tenant with GA. This requires an app consent to the Microsoft Application: Microsoft Graph PowerShell - 14d82eec-204b-4c2f-b7e8-296a70dab67e.
The Graph API scopes needed are: Policy.Read.All, Policy.Read.All, Directory.Read.All, Agreement.Read.All, Application.Read.All

.EXAMPLE
Get-CatPSConditionalAccessReport.ps1 -tenant
Loading Modules
Authenticating
Getting CA Policies
Getting SPs
Complete. Report is located at <path>

#>
Function Get-CBCAPolicyReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Tenant,

        # Report Path. Defaults to the current directory.
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string]
        $ReportPath = (Get-Location).Path
    )

    $InformationPreference = 'Continue'
    Write-Information "Loading Microsoft Graph SDK for PowerShell. This may take a few minutes..."
    # Switch to beta endpoint
    Select-MgProfile -Name Beta

    # Clear any existing sessions. The Graph module chaches the tenant you've connected to. Not ever certain where this is stored. Need to dig into this more. Nothing in the docs.

    Write-Information "Authenticating"
    try {
        Connect-MgGraph -tenant $Tenant -Scopes "Policy.Read.All", "Directory.Read.All", "Agreement.Read.All", "Application.Read.All" -ErrorAction Stop
    }
    catch {
        throwUser "Error Connecting to Graph"
    }


    # Get Org Information
    $org = Get-MgBetaOrganization

    Write-Information "Organization: $($org.DisplayName)"
    Write-Information "TenantID: $($org.Id)"


    # Fetch conditional access policies.
    Write-Information "Getting CA Policies"
    $caPolicies = Get-MgBetaIdentityConditionalAccesspolicy -All

    # Fetch service principals for id translation.
    Write-Information "Getting SPs"
    $enterpriseApps = Get-MgBetaServicePrincipal -All

    # Get directory role temaples for id translation.
    Write-Information "Getting Directory Role Templates"
    $directoryRoleTemplates = Get-MgBetaDirectoryRoleTemplate -All

    # Collection to hold results.
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Counters for progress
    $policyCount = $caPolicies.Count
    $i = 1


    # Loop through each policy, generating a object
    foreach ($policy in $caPolicies) {
        Write-Progress -Activity "Processing Policies" -PercentComplete (($i / $policyCount) * 100) -Status "Policy $i out of $policyCount - $($policy.displayName)"
        $result = [PSCustomObject]@{
            'id'                                             = $policy.id
            'displayName'                                    = $policy.displayName
            'state'                                          = $policy.state
            'createdDateTime'                                = $policy.createdDateTime
            'modifiedDateTime'                               = $policy.modifiedDateTime
            # conditions
            
            'includeUsers'                                   = $(
                $items = [System.Collections.Generic.List[string]]::new()

                # Only look up the non-generic names
                foreach ($User in $policy.conditions.users.includeUsers) {
                    if ($User -ne 'All' -and $User -ne 'GuestsOrExternalUsers' -and $User -ne 'None') {
                        $items.add((Get-MgUser -UserId $User).userPrincipalName)
                    }
                    else {
                        $items.Add($user)
                    }
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            # Same process for all user/group lookups. Exclude generics.
            'excludeUsers'                                   = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($User in $policy.conditions.users.excludeUsers) {
                    if ($User -ne 'All' -and $User -ne 'GuestsOrExternalUsers' -and $User -ne 'None') {
                        $items.add((Get-MgUser -UserId $User).userPrincipalName)
                    }
                    else {
                        $items.add($User)
                    }
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            'includegroups'                                  = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($group in $policy.conditions.users.includegroups) {
                    if ($group -ne 'All' -and $group -ne 'None') {
                        $items.Add((Get-Mggroup -groupId $group).displayName)
                    }
                    else {
                        $items.Add($group)
                    }
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )

            'excludegroups'                                  = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($group in $policy.conditions.users.excludegroups) {
                    if ($group -ne 'All' -and $group -ne 'None') {
                        $items.Add((Get-Mggroup -groupId $group).displayName)
                    }
                    else {
                        $items.Add($group)
                    }
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            #'includeRoles' = $(if ($null -ne $policy.conditions.users.includeRoles) { [String]::join("`n", $policy.conditions.users.includeRoles) })
            #'excludeRoles' = $(if ($null -ne $policy.conditions.users.excludeRoles) { [String]::join("`n", $policy.conditions.users.excludeRoles) })
            'includeRoles'                                   = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($role in $policy.conditions.users.includeRoles) {
                    $items.Add(($directoryRoleTemplates | where-object { $_.Id -eq $role }).displayName)
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            'excludeRoles'                                   = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($role in $policy.conditions.users.excludeRoles) {
                    $items.Add(($directoryRoleTemplates | where-object { $_.Id -eq $role }).displayName)
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )

            'includeGuestsOrExternalUsers'                   = $policy.conditions.users.includeGuestsOrExternalUsers
            'excludeGuestsOrExternalUsers'                   = $policy.conditions.users.excludeGuestsOrExternalUsers

            'includeApplications'                            = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($application in $policy.conditions.applications.includeApplications) {
                    if ($application -ne 'None' -and $application -ne 'All' -and $application -ne 'Office365') {
                        $items.Add(($EnterpriseApps | Where-Object { $_.appID -eq $application }).displayName)
                    }
                    else {
                        $items.Add($application)
                    }
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            'excludeApplications'                            = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($application in $policy.conditions.applications.excludeApplications) {
                    if ($application -ne 'None' -and $application -ne 'All' -and $application -ne 'Office365') {
                        $items.Add(($EnterpriseApps | Where-Object { $_.appID -eq $application }).displayName)
                    }
                    else {
                        $items.Add($application)
                    }
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            'includeUserActions'                             = $(if ($null -ne $policy.conditions.applications.includeUserActions) { [String]::join("`n", $policy.conditions.applications.includeUserActions) })
            'userRiskLevels'                                 = $(if ($null -ne $policy.conditions.userRiskLevels) { [String]::join("`n", $policy.conditions.userRiskLevels) })
            'InsiderRiskLevels'                              = $(if ($null -ne $policy.conditions.InsiderRiskLevels) { [String]::join("`n", $policy.conditions.InsiderRiskLevels) })
            'ServicePrincipalRiskLevels'                     = $(if ($null -ne $policy.conditions.ServicePrincipalRiskLevels) { [String]::join("`n", $policy.conditions.ServicePrincipalRiskLevels) })
            'signInRiskLevels'                               = $(if ($null -ne $policy.conditions.signInRiskLevels) { [String]::join("`n", $policy.conditions.signInRiskLevels) })
            'includePlatforms'                               = $(if ($null -ne $policy.conditions.platforms.includePlatforms) { [String]::join("`n", $policy.conditions.platforms.includePlatforms) })
            'excludePlatforms'                               = $(if ($null -ne $policy.conditions.platforms.excludePlatforms) { [String]::join("`n", $policy.conditions.platforms.excludePlatforms) })
            'clientAppTypes'                                 = $(if ($null -ne $policy.conditions.clientAppTypes) { [String]::join("`n", $policy.conditions.clientAppTypes) })
            'includeLocations'                               = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($location in $policy.conditions.locations.includelocations) {
                    if ($location -ne 'All' -and $location -ne 'AllTrusted' -and $location -ne '00000000-0000-0000-0000-000000000000') {
                        $items.Add((Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $location).displayName)
                    }
                    # location with all zeros is a legacy MFA trusted IP range
                    elseif ($location -eq '00000000-0000-0000-0000-000000000000') {
                        $items.Add('MFA Trusted IPs')
                    }
                    else {
                        $items.Add($location)
                    }
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            'excludeLocations'                               = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($location in $policy.conditions.locations.excludeLocations) {
                    if ($location -ne 'All' -and $location -ne 'AllTrusted' -and $location -ne '00000000-0000-0000-0000-000000000000') {
                        $items.Add((Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $location).displayName)
                    }
                    elseif ($location -eq '00000000-0000-0000-0000-000000000000') {
                        $items.Add('MFA Trusted IPs')
                    }
                    else {
                        $items.Add($location)
                    }
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            'AuthenticationFlows'                            = $(if ($null -ne $policy.conditions.AuthenticationFlows.TransferMethods) { [String]::join("`n", $policy.conditions.AuthenticationFlows.TransferMethods) })            
            'grantControls'                                  = $(if ($null -ne $policy.grantControls.builtInControls) { [String]::join("`n", $policy.grantControls.builtInControls) })
            'termsOfUses'                                    = $(
                $items = [System.Collections.Generic.List[string]]::new()
                foreach ($TermsOfUse in $policy.grantControls.termsOfUse) {
                    $items.Add((Get-MgAgreement -AgreementId $TermsOfUse).displayName)
                }
                if ($items.count -gt 0) { [String]::join("`n", $items) }
            )
            'operator'                                       = $policy.grantControls.operator
            'sessionControlsapplicationEnforcedRestrictions' = $policy.sessionControls.applicationEnforcedRestrictions.isEnabled
            'sessionControlscloudAppSecurity'                = $policy.sessionControls.cloudAppSecurity.isEnabled
            'sessionControlssignInFrequencyEnabled'          = $policy.sessionControls.signInFrequency.IsEnabled
            'sessionControlssignInFrequencyType'             = $policy.sessionControls.signInFrequency.Type
            'sessionControlssignInFrequencyValue'            = $policy.sessionControls.signInFrequency.Value
            'sessionControlspersistentBrowserEnabled'        = $policy.sessionControls.persistentBrowser.IsEnabled
            'sessionControlspersistentBrowserMode'           = $policy.sessionControls.persistentBrowser.Mode
        }

        # Add results to collection
        $results.Add($result)

        # Inc the counter
        $i++
    }

    # Export the result to Excel.
    # TODO Format the output to be more readable. Word wrap the text in the cells.

    $reportFullPath = ([String]::Format("Conditional Access policy Design Report {0} - Generated on {1}.xlsx", $org.DisplayName, (get-date).ToString('s')))
    $reportFullPath = "$ReportPath\" + [String]::join('_', $reportFullPath.Split([IO.Path]::GetInvalidFileNameChars()))
    $Results | Export-Excel -Path $reportFullPath -WorksheetName "CA Policies" -BoldTopRow -FreezeTopRow -AutoFilter -AutoSize -ClearSheet
    Write-Information "Complete. Report is located at $reportFullPath"


}
