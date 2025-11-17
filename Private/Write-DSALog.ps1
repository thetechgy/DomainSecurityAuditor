function Write-DSALog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFile,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "{0} [{1}] {2}" -f $timestamp, $Level.ToUpperInvariant(), $Message

    $logDirectory = Split-Path -Path $LogFile -Parent
    if (-not (Test-Path -Path $logDirectory)) {
        $null = New-Item -ItemType Directory -Path $logDirectory -Force
    }

    Add-Content -Path $LogFile -Value $entry
    if ($PSBoundParameters.ContainsKey('Verbose') -or $VerbosePreference -ne 'SilentlyContinue') {
        Write-Verbose -Message $entry
    }
}
