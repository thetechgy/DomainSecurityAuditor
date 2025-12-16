<#
.SYNOPSIS
    Test whether a PSObject has a specific property.
.DESCRIPTION
    Checks if the input object has a property with the given name, reducing boilerplate for the common
    pattern of checking $obj.PSObject.Properties.Name -contains 'PropertyName'.
.PARAMETER InputObject
    Object to check for the property.
.PARAMETER Name
    Name of the property to look for.
.OUTPUTS
    Boolean indicating whether the property exists on the object.
#>
function Test-DSAProperty {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $false
    }

    if ($InputObject -is [hashtable]) {
        return $InputObject.ContainsKey($Name)
    }

    return $InputObject.PSObject -and $InputObject.PSObject.Properties.Name -contains $Name
}

<#
.SYNOPSIS
    Retrieve a property value from objects or hashtables with optional conversion.
.DESCRIPTION
    Iterates candidate property names on hashtables or PSObjects, returning a default or converted value when not present.
.PARAMETER InputObject
    Object or hashtable containing the property.
.PARAMETER PropertyName
    Property name(s) to attempt in order.
.PARAMETER Default
    Value returned when the property is absent.
.PARAMETER As
    Optional type to cast the value to before returning.
#>
function Get-DSAPropertyValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$PropertyName,

        $Default = $null,

        [Type]$As
    )

    if ($null -eq $InputObject -or -not $PropertyName) {
        return $Default
    }

    foreach ($name in $PropertyName) {
        if ($InputObject -is [hashtable]) {
            if ($InputObject.ContainsKey($name)) {
                $value = $InputObject[$name]
                return (Convert-DSAPropertyValue -Value $value -As $As -Default $Default)
            }
        }
        elseif ($InputObject.PSObject -and $InputObject.PSObject.Properties.Name -contains $name) {
            $value = $InputObject.$name
            return (Convert-DSAPropertyValue -Value $value -As $As -Default $Default)
        }
    }

    return $Default
}

<#
.SYNOPSIS
    Convert a value to a specific type with a default fallback.
.DESCRIPTION
    Attempts to cast the supplied value to a requested type, returning a default when conversion yields null.
.PARAMETER Value
    Input value to convert.
.PARAMETER As
    Type to cast the value to.
.PARAMETER Default
    Fallback value when the cast fails or the input is null.
#>
function Convert-DSAPropertyValue {
    [CmdletBinding()]
    param (
        $Value,
        [Type]$As,
        $Default = $null
    )

    if (-not $As) {
        return $(if ($null -eq $Value) { $Default } else { $Value })
    }

    $result = $Value -as $As
    return $(if ($null -eq $result) { $Default } else { $result })
}

<#
.SYNOPSIS
    Extract a TTL value from common DNS-related property names.
.DESCRIPTION
    Searches candidate TTL property names on an object/hashtable and returns an integer value or default when absent.
    Uses the centralized $script:DSATtlCandidateNames from DSA.ModuleState.ps1 as the single source of truth.
.PARAMETER InputObject
    Object that may contain TTL properties.
.PARAMETER PropertyName
    Optional additional property names to search (appended to the standard candidates).
.PARAMETER Default
    Value to return when no TTL is found.
#>
function Get-DSATtlValue {
    [CmdletBinding()]
    param (
        $InputObject,
        [string[]]$PropertyName,
        $Default = $null
    )

    $candidateNames = $script:DSATtlCandidateNames
    if ($PropertyName) {
        $candidateNames = @($candidateNames + $PropertyName)
    }

    return Get-DSAPropertyValue -InputObject $InputObject -PropertyName $candidateNames -Default $Default -As ([int])
}
