param(	
    [Alias("t")]
    [switch] $transcribe = $false,
	
    [Alias("h")]
    [switch] $help = $false
)

if ($help) {
    Write-Output ("`t Configured a baseline set of IAM policies")
    Write-Output ("`t Prerequisites: Powershell, aws-api-session-management, included setup.ps1")
    Write-Output ("`t ")
    Write-Output ("`t Parameters:")
    Write-Output ("`t ")
    Write-Output ("`t transcribe")
    Write-Output ("`t     If set, creates a transcript of the script.")
    Write-Output ("`t     Default: {0}" -f $transcribe)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -transcribe {1}" -f $MyInvocation.MyCommand.Name, $transcribe)
    Write-Output ("`t     Example: .\{0}.ps1 -t {1}" -f $MyInvocation.MyCommand.Name, $transcribe)

    return $false
}

# navigate to library root
cd $PSScriptRoot

# load necessary modules
.\import-required-modules.ps1

# Check if we are transcribing
if($transcribe) {
    $transcriptName = ("{0}-{1}.transcript" -f $MyInvocation.MyCommand.Name, [DateTimeOffset]::Now.ToUnixTimeSeconds())
    Start-Transcript -Path $transcriptName
}

Write-Output ("`t Configuring IAM password policy...")

$passwordPolicy = @{ 
    'AllowUsersToChangePassword' = $true;
    'HardExpiry'                 = $false;
    'MaxPasswordAge'             = 90;
    'MinimumPasswordLength'      = 64;
    'PasswordReusePrevention'    = 24;
    'RequireLowercaseCharacter'  = $true;
    'RequireNumber'              = $true;
    'RequireSymbol'              = $true;
    'RequireUppercaseCharacter'  = $true;
}

$passwordPolicy | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders

# Set password policy
Update-IAMAccountPasswordPolicy @passwordPolicy 

Write-Output ("`t Password policy set")

# Check if we are transcribing
if($transcribe) {
    Stop-Transcript
}

#True for success
return $true