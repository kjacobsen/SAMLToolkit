<#
    Things that would be nice to see:
    - Command Splatting
    - null comparision - always fun
#>

<#
    TODO
    This one will remain internal, but we should clean it up
#>
function Test-URI ($URI) 
{
    try 
    {
        $Response = Invoke-WebRequest -Uri $URI -TimeoutSec 10
        $Response.statuscode -eq 200
    }
    catch 
    {
        $false
    }
}

<#
    TODO:
    - Comments
#>
function Save-SAMLFederationMetadata
{
    <#
        .SYNOPSIS
        Short description
        .DESCRIPTION
        Long description
        .EXAMPLE
        C:\PS> <example usage>
        Explanation of what the example does
        .OUTPUTS
        Output (if any)
    #>
    [CmdletBinding()]
    param
    (
        # AAD Tenant Address (format is client.onmicrosoft.com)
        [Parameter(Mandatory = $true, ParameterSetName = 'AzureAD')]
        [ValidateScript({
                    $_.contains('.onmicrosoft.com')
        })]
        [String]
        $AADTenant,
        
        # Hostname of the ADFS server (login.contoso.com)
        [Parameter(Mandatory = $true, ParameterSetName = 'ADFS')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Hostname,
        
        # URI of the identity providers federation metadata
        [Parameter(Mandatory = $true, ParameterSetName = 'URI')]
        [ValidateNotNullOrEmpty()]
        [URI]
        $URI,
        
        # Path to save the federation metadata to (if not specified, saved to $ENV:Temp\federation.xml)
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )
    
    switch ($PSCmdlet.ParameterSetName) 
    {
        'AzureAD' 
        {  
            $BaseURL = 'https://login.microsoftonline.com/{0}/FederationMetadata/2007-06/FederationMetadata.xml'
            $URI = [URI]($BaseURL -f $AADTenant)
        }
        'ADFS' 
        {  
            $BaseURL = 'https://{0}/FederationMetadata/2007-06/FederationMetadata.xml'
            $URI = [URI]($BaseURL -f $Hostname)
        }
    }
    
    Write-Verbose -Message "Federation Metadata URL: $URI"
    
    if (-not $PSBoundParameters.ContainsKey('path'))
    {
        $Path = Join-Path -Path $ENV:temp -ChildPath 'federation.xml'
        Write-Verbose -Message "Federation Metadata file saved to: $Path"
        if (Test-Path -Path $Path)
        {
            Write-Warning -Message 'Overwritting file'
        }
    }

    try 
    {
        Invoke-WebRequest -Uri $URI -OutFile $Path -ErrorAction Stop
    }
    catch 
    {
        Throw 'Unable to download the federation metadata'
    }
}

<#
    TODO:
    - Write-progress
    - Comments
    - pipeline input?
#>
function Test-SAMLFederationEndpoint
{
    <#
        .SYNOPSIS
        Short description
        .DESCRIPTION
        Long description
        .EXAMPLE
        C:\PS> <example usage>
        Explanation of what the example does
        .OUTPUTS
        Output (if any)
    #>
    [CmdletBinding()]
    param
    (       
        # Path to the federation metadata
        [Parameter(Mandatory = $true, ParameterSetName = 'PATH')]
        [ValidateScript({
                    Test-Path -Path $_
        })]
        [String]
        $Path
    )
    
    # Read the metadata in
    try 
    {
        $FederationMetaData = Select-Xml -Path $Path -XPath /
    }
    catch 
    {
        Throw 'Unable to read federation metadata file'
    }
    
    $EntityID = [PSCustomObject]@{
        EndpointName = 'EntityID'
        Address      = $FederationMetaData.Node.EntityDescriptor.entityID
        Available    = (Test-URI $FederationMetaData.Node.EntityDescriptor.entityID)
    }
    Write-Output -InputObject $EntityID
    
    $SecurityTokenServiceType = $FederationMetaData.Node.EntityDescriptor.RoleDescriptor | Where-Object -FilterScript {
        $_.Type -eq 'fed:SecurityTokenServiceType'
    }
    
    $SecurityTokenServiceEndpointAddress = $SecurityTokenServiceType.SecurityTokenServiceEndpoint.EndpointReference.Address
    $SecurityTokenServiceEndpoint = [PSCustomObject]@{
        EndpointName = 'SecurityTokenService'
        Address      = $SecurityTokenServiceEndpointAddress
        Available    = (Test-URI $SecurityTokenServiceEndpointAddress) 
    }
    Write-Output -InputObject $SecurityTokenServiceEndpoint
    
    $PassiveRequestorEndpointAddress = $SecurityTokenServiceType.PassiveRequestorEndpoint.EndpointReference.Address
    $PassiveRequestorEndpoint = [PSCustomObject]@{
        EndpointName = 'PassiveRequestor'
        Address      = $PassiveRequestorEndpointAddress
        Available    = (Test-URI $PassiveRequestorEndpointAddress) 
    }
    Write-Output -InputObject $PassiveRequestorEndpoint
    
    $ApplicationService = $FederationMetaData.Node.EntityDescriptor.RoleDescriptor | Where-Object -FilterScript {
        $_.Type -eq 'fed:ApplicationServiceType'
    }

    $ApplicationServiceEndpointAddress = $ApplicationService.ApplicationServiceEndpoint.EndpointReference.Address
    $ApplicationServiceEndpoint = [PSCustomObject]@{
        EndpointName = 'ApplicationService'
        Address      = $ApplicationServiceEndpointAddress
        Available    = (Test-URI $ApplicationServiceEndpointAddress) 
    }
    Write-Output -InputObject $ApplicationServiceEndpoint
    
    $TargetScopes = $ApplicationService.TargetScopes.EndpointReference
    foreach ($TargetScope in $TargetScopes) 
    {
        $TargetScopeEndpoint = [PSCustomObject]@{
            EndpointName = 'TargetScope'
            Address      = $TargetScope.address
            Available    = (Test-URI $TargetScope.address) 
        }
        Write-Output -InputObject $TargetScopeEndpoint
    }
}
