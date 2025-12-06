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
        } elseif ($InputObject.PSObject -and $InputObject.PSObject.Properties.Name -contains $name) {
            $value = $InputObject.$name
            return (Convert-DSAPropertyValue -Value $value -As $As -Default $Default)
        }
    }

    return $Default
}

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
