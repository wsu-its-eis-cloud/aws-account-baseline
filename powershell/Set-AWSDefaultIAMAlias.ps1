param(	
    [Alias("a")]
    [string] $accountName = "",

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
    Write-Output ("`t accountName")
    Write-Output ("`t     The name of the AWS account, e.g., its-aws-demo.  Used for setting signin-in alias.")
    Write-Output ("`t     Default: {0}" -f $sessionName)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -accountName {1}" -f $MyInvocation.MyCommand.Name, $accountName)
    Write-Output ("`t     Example: .\{0}.ps1 -a {1}" -f $MyInvocation.MyCommand.Name, $accountName)
    Write-Output ("`t ")
    Write-Output ("`t transcribe")
    Write-Output ("`t     If set, creates a transcript of the script.")
    Write-Output ("`t     Default: {0}" -f $transcribe)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -transcribe {1}" -f $MyInvocation.MyCommand.Name, $transcribe)
    Write-Output ("`t     Example: .\{0}.ps1 -t {1}" -f $MyInvocation.MyCommand.Name, $transcribe)

    return $false
}

# Prompt for account name if not specified
if ($accountName -eq "") {
	$accountName = Read-Host "Enter the account name, e.g., its-aws-demo"
}
$accountName = $accountName.ToLower()

# navigate to library root
cd $PSScriptRoot

# load necessary modules
.\import-required-modules.ps1

# Check if we are transcribing
if($transcribe) {
    $transcriptName = ("{0}-{1}.transcript" -f $MyInvocation.MyCommand.Name, [DateTimeOffset]::Now.ToUnixTimeSeconds())
    Start-Transcript -Path $transcriptName
}

Write-Output ("`t Setting account alias...")

# Get existing alias
$accountAlias = Get-IAMAccountAlias 

# Check if alias is already set, if not, set it
if($accountAlias -ne $accountName) {
    New-IAMAccountAlias -AccountAlias $accountName 
}

Write-Output ("`t Alias set")

# Check if we are transcribing
if($transcribe) {
    Stop-Transcript
}

#True for success
return $true