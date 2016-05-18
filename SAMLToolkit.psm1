function Test-URI {
    <#
        .SYNOPSIS
        Tests if a URI is available to web requests.
        .DESCRIPTION
        Performs a web request on the specified URI, if the response code is 200, returns true, else if any issues ocurr, returns false.
        .EXAMPLE
        C:\PS> Test-URI 'http://microsoft.com'
        Explanation of what the example does
        .INPUTS
        Accepts Strings of URIs from the pipeline
        .OUTPUTS
        Outputs boolean values if endpoint is available
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]
    param (
        # URI to test connectivity
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]
        $URI
    )

    process {
        try {
            $Response = Invoke-WebRequest -Uri $URI -TimeoutSec 10
            $Response.statuscode -eq 200
        }
        catch {
            $false
        }
    }
}

function Save-SAMLFederationMetadata {
    <#
        .SYNOPSIS
        Downloads the federation metadata from a specified location
        .DESCRIPTION
        This CMDLet downloads the federation metadata for a specified AAD Tenant, ADFS hostname or specified URI. You can specify either
        an AAD tenant name (in the format of contoso.onmicrosoft.com), the hostname of an ADFS server (in the format of adfs.contoso.com),
        or specify a specific URI.
        .EXAMPLE
        C:\PS> Save-SAMLFederationMetadata -AADTenant contoso.onmicrosoft.com
        Saves the AAD federation metadata for the tenant, contoso.onmicrosoft.com. 
        .EXAMPLE
        C:\PS> Save-SAMLFederationMetadata -Hostname login.consoto.com
        Saves the ADFS based federation metadata from the adfs server with hostname login.contoso.com
        .EXAMPLE
        C:\PS> Save-SAMLFederationMetadata -URI https://login.contoso.com/FederationMetadata/2007-06/FederationMetadata.xml
        Saves the federation metadata from the specified URI
    #>
    [CmdletBinding(DefaultParameterSetName='AzureAD')]
    param (
        # AAD Tenant Address (format is client.onmicrosoft.com)
        [Parameter(Mandatory = $true, ParameterSetName = 'AzureAD')]
        [ValidateScript({ $_.contains('.onmicrosoft.com') })]
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
    
    # If AzureAD or ADFS, build the URI from specified inputs
    switch ($PSCmdlet.ParameterSetName) {
        'AzureAD' {  
            $BaseURL = 'https://login.microsoftonline.com/{0}/FederationMetadata/2007-06/FederationMetadata.xml'
            $URI = [URI]($BaseURL -f $AADTenant)
        }
        'ADFS' {  
            $BaseURL = 'https://{0}/FederationMetadata/2007-06/FederationMetadata.xml'
            $URI = [URI]($BaseURL -f $Hostname)
        }
    }
    
    Write-Verbose -Message "Federation Metadata URL: $URI"
    
    # If path is not specified, then save to temp directory.
    if (-not $PSBoundParameters.ContainsKey('path')) {
        $Path = Join-Path -Path $ENV:temp -ChildPath 'federation.xml'
        Write-Verbose -Message "Federation Metadata file saved to: $Path"
    }
    
    # Warn the user if overwriting the file (we will continue)
    if (Test-Path -Path $Path) {
        Write-Warning -Message 'Overwritting file'
    }

    # Download the metadata from the URI to the specified path
    try {
        Invoke-WebRequest -Uri $URI -OutFile $Path -ErrorAction Stop
    }
    catch {
        Throw 'Unable to download the federation metadata'
    }
}

function Test-SAMLFederationEndpoint {
    <#
        .SYNOPSIS
        Tests the availability of each endpoint specified in a federation metadata file.
        .DESCRIPTION
        There are a number of endpoints specifed within a federation metadata file. This CMDLet will read a metadata file and test if
        each of the specifed endpoints are available.
        .EXAMPLE
        C:\PS> Test-SAMLFederationEndpoint -Path C:\federation.xml
        Tests the endpoints listed within the file, c:\federation.xml
        .OUTPUTS
        Array of [PSCustomObject] objects containing the name of the endpoint, address and if it is accessible.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (       
        # Path to the federation metadata
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $Path
    )
    
    # Read the metadata file in using Select-XML
    try {
        $FederationMetaData = Select-Xml -Path $Path -XPath /
    }
    catch {
        Throw 'Unable to read federation metadata file'
    }
    
    # Get the EntityID, and test its availability, and then write the output
    Write-Progress -Activity 'Testing Federation Endpoints' -Status 'Testing EntityID'
    $EntityIDAddress = $FederationMetaData.Node.EntityDescriptor.entityID
    $EntityID = [PSCustomObject]@{
        EndpointName = 'EntityID'
        Address      = $EntityIDAddress 
        Available    = Test-URI $EntityIDAddress
    }
    $EntityID
    
    # Get the SecurityTokenServiceType entity within the federation data
    $SecurityTokenServiceType = $FederationMetaData.Node.EntityDescriptor.RoleDescriptor | Where-Object -FilterScript { $_.Type -eq 'fed:SecurityTokenServiceType' }
    
    # Get the SecurityTokenService Endpoint, tests its availability and write the output
    Write-Progress -Activity 'Testing Federation Endpoints' -Status 'Testing SecurityTokenService endpoint'
    $SecurityTokenServiceEndpointAddress = $SecurityTokenServiceType.SecurityTokenServiceEndpoint.EndpointReference.Address
    $SecurityTokenServiceEndpoint = [PSCustomObject]@{
        EndpointName = 'SecurityTokenService'
        Address      = $SecurityTokenServiceEndpointAddress
        Available    = Test-URI $SecurityTokenServiceEndpointAddress 
    }
    $SecurityTokenServiceEndpoint
    
    # Get the PassiveRequestorEndpoint, test its availability and write the output
    Write-Progress -Activity 'Testing Federation Endpoints' -Status 'Testing PassiveRequestor endpoint'
    $PassiveRequestorEndpointAddress = $SecurityTokenServiceType.PassiveRequestorEndpoint.EndpointReference.Address
    $PassiveRequestorEndpoint = [PSCustomObject]@{
        EndpointName = 'PassiveRequestor'
        Address      = $PassiveRequestorEndpointAddress
        Available    = Test-URI $PassiveRequestorEndpointAddress 
    }
    $PassiveRequestorEndpoint
    
    # Get the ApplicationServiceType entity within the federation data
    $ApplicationService = $FederationMetaData.Node.EntityDescriptor.RoleDescriptor | Where-Object -FilterScript { $_.Type -eq 'fed:ApplicationServiceType' }

    # Get the ApplicationServiceEndpoint, test its availability and write the output
    Write-Progress -Activity 'Testing Federation Endpoints' -Status 'Testing ApplicationService endpoint'
    $ApplicationServiceEndpointAddress = $ApplicationService.ApplicationServiceEndpoint.EndpointReference.Address
    $ApplicationServiceEndpoint = [PSCustomObject]@{
        EndpointName = 'ApplicationService'
        Address      = $ApplicationServiceEndpointAddress
        Available    = Test-URI $ApplicationServiceEndpointAddress 
    }
    $ApplicationServiceEndpoint
    
    # Get the target scopes under the applicationservice, for each, test and write the output
    Write-Progress -Activity 'Testing Federation Endpoints' -Status 'Testing TargetScopes'
    $TargetScopes = $ApplicationService.TargetScopes.EndpointReference
    foreach ($TargetScope in $TargetScopes) {
        $TargetScopeEndpoint = [PSCustomObject]@{
            EndpointName = 'TargetScope'
            Address      = $TargetScope.address
            Available    = Test-URI $TargetScope.address 
        }
        $TargetScopeEndpoint
    }
    
    Write-Progress -Activity 'Testing Federation Endpoints' -Completed
}
