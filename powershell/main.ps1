param(
    [Alias("a")]
    [string] $accountName = "",
	
	[Alias("c")]
    [string] $accountType = "",

    [Alias("s")]
    [string] $sessionName = "awsDefaultSession",

    [Alias("t")]
    [switch] $transcribe = $true,
	
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
	Write-Output ("`t accountType")
    Write-Output ("`t     The type of AWS account, e.g., billing, peering, shared, isolated")
    Write-Output ("`t     Default: {0}" -f $sessionName)
    Write-Output ("`t     Alias: c")
    Write-Output ("`t     Example: .\{0}.ps1 -accountType {1}" -f $MyInvocation.MyCommand.Name, $accountType)
    Write-Output ("`t     Example: .\{0}.ps1 -a {1}" -f $MyInvocation.MyCommand.Name, $accountType)
    Write-Output ("`t ")
    Write-Output ("`t sessionName")
    Write-Output ("`t     The name of the global variable that stores the MFA validated AWS session.")
    Write-Output ("`t     Default: {0}" -f $sessionName)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -sessionName {1}" -f $MyInvocation.MyCommand.Name, $sessionName)
    Write-Output ("`t     Example: .\{0}.ps1 -s {1}" -f $MyInvocation.MyCommand.Name, $sessionName)Write-Output ("`t ")
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

# Prompt for account type if not specified
$accountType = $accountType.ToLower()
while ($accountType -ne "billing" -AND $accountType -ne "peering" -AND $accountType -ne "peering" -AND $accountType -ne "isolated") {
	$accountType = Read-Host "Enter the type of account (billing, peering, shared, isolated):"
	$accountType = $accountType.ToLower()
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

Write-Output ("")
Write-Output ("Deleting default VPC's from account.")
.\Delete-AWSDefaultVPCs.ps1
Write-Output ("VPC's deleted.")
Write-Output ("")

Write-Output ("")
Write-Output ("Configuring default IAM password policy.")
.\Set-AWSDefaultIAMPasswordPolicy.ps1
Write-Output ("Policy set.")
Write-Output ("")

Write-Output ("")
Write-Output ("Setting the account alias.")
.\Set-AWSDefaultIAMAlias.ps1 -accountName $accountName
Write-Output ("Alias set.")
Write-Output ("")

Write-Output ("")
Write-Output ("Creating default IAM objects.")
.\Create-AWSDefaultIAMObjects.ps1
Write-Output ("IAM Objects set.")
Write-Output ("")

Write-Output ("")
Write-Output ("Configuring compliance policies.")
.\Set-AWSDefaultAuditConfig.ps1 -accountType $accountType
Write-Output ("Compliance policy set.")
Write-Output ("")

# Soft-deprecation of dynamic access functionality - probably no further need.
#Write-Output ("")
#Write-Output ("Enabling dynamic service access.")
#.\Enable-AWSDynamicServiceAccess.ps1
#Write-Output ("Dynamic service access set.")
#Write-Output ("")

# Build final checklist
$checklist = Get-Content -Raw _ChecklistTemplate.csv
$signinlink = ("https://{0}.signin.aws.amazon.com/console" -f $accountName)
$checklist = $checklist.Replace("{signinlink}", $signinlink)
$checklistName = ("{0}-Checklist.csv" -f $accountName)
$checklist | Set-Content $checklistName
$packetName = ("AccountBaselinePacket-{0}-{1}.zip" -f $accountName, [DateTimeOffset]::Now.ToUnixTimeSeconds())

# Check if we are transcribing
if($transcribe) {
    Stop-Transcript
    Start-Sleep 2
}

# Build account baseline packet
Get-ChildItem -Exclude _*,.*,*.md | Compress-Archive -DestinationPath $packetName -Force
rm *.transcript
rm $checklistName

#True for success
return $true