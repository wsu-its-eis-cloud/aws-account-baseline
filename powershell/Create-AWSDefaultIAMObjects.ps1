param(	
	[Alias("s")]
    [string] $sessionName = "awsDefaultSession",
	
    [Alias("h")]
    [switch] $help = $false
)

if ($help) {
    Write-Output ("`t Configured a baseline set of IAM policies")
    Write-Output ("`t Prerequisites: Powershell, aws-api-session-management, included setup.ps1")
    Write-Output ("`t ")
    Write-Output ("`t Parameters:")
    Write-Output ("`t ")
    Write-Output ("`t sessionName")
    Write-Output ("`t     The name of the global variable that stores the MFA validated AWS session.")
    Write-Output ("`t     Default: {0}" -f $sessionName)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -sessionName {1}" -f $MyInvocation.MyCommand.Name, $sessionName)
    Write-Output ("`t     Example: .\{0}.ps1 -s {1}" -f $MyInvocation.MyCommand.Name, $sessionName)

    return $false
}

# navigate to library root
cd $PSScriptRoot

# load necessary modules
.\import-required-modules.ps1

# Start the transcript
$transcriptName = ("{0}-{1}.transcript" -f $MyInvocation.MyCommand.Name, [DateTimeOffset]::Now.ToUnixTimeSeconds())
Start-Transcript -Path $transcriptName

# Retrieve specified AWS STS session
$globalSession = $null
$expression = ("`$globalSession = `$global:{0}" -f $sessionName)
Invoke-Expression -Command $expression

# If the session is null, return false
if($globalSession -eq $null) {
    Write-Output ("`t Failed to retrieve specified AWS session.")

    Stop-Transcript
    return $false
}

# Creating session hashtable for parameter splatting
$session = @{
    'AccessKey'    = $globalSession.AccessKeyId;
    'SecretKey'    = $globalSession.SecretAccessKey;
    'SessionToken' = $globalSession.SessionToken;
}

Write-Output ("`t Creating baseline policy objects...")

# Retrieve account ID
$account = (Get-STSCallerIdentity @session).Account

# Create WSU policies
$usWestAdmin = New-IAMPolicy -PolicyName WsuRegionUsWest2ScopedAdministrator -PolicyDocument (Get-content -Raw WsuRegionUsWest2ScopedAdministrator.json) @session -Force
$cloudwatchAdmin = New-IAMPolicy -PolicyName WsuRegionUsEast1CloudWatchAdmin -PolicyDocument (Get-content -Raw WsuRegionUsEast1CloudWatchAdmin.json) @session -Force
$disableRegionsPolicy = New-IAMPolicy -PolicyName WsuRegionDisableAll -PolicyDocument (Get-content -Raw WsuRegionDisableAll.json) @session -Force
$accountPortalPolicy = New-IAMPolicy -PolicyName WsuAccountPortalFullAccess -PolicyDocument (Get-content -Raw WsuAccountPortalFullAccess.json) @session -Force

# Create groups
$adminGroup = New-IAMGroup -GroupName Administrators @session -Force
$financialAdminGroup = New-IAMGroup -GroupName FinancialAdministrators @session -Force
$supportAccessGroup = New-IAMGroup -GroupName SupportAccess @session -Force

# Create service-linked roles
$accessAnalyzerRole = New-IAMServiceLinkedRole -AWSServiceName access-analyzer.amazonaws.com @session
$guardDutyRole = New-IAMServiceLinkedRole -AWSServiceName guardduty.amazonaws.com @session
$configServiceRole = New-IAMServiceLinkedRole -AWSServiceName config.amazonaws.com @session
$securityHubRole = New-IAMServiceLinkedRole -AWSServiceName securityhub.amazonaws.com @session

# Create support access role
$supportAccessRole = New-IAMRole -RoleName AWSSupportAccessRole -AssumeRolePolicyDocument (Get-content -Raw AWSSupportAccessRole-TrustPolicyDocument.json).Replace("{accountid}", $account) @session

# Pause to allow custom objects to propogate
Write-Output ("`t Waiting for objects to propogate...")
Start-Sleep -Seconds 5

# Register policies on administrators group
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn $usWestAdmin.Arn @session -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn $cloudwatchAdmin.Arn @session -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn $disableRegionsPolicy.Arn @session -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn arn:aws:iam::aws:policy/IAMFullAccess @session -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn arn:aws:iam::aws:policy/AmazonS3FullAccess @session -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn arn:aws:iam::aws:policy/job-function/Billing @session -Force

# Register policies on financial administrators group
Register-IAMGroupPolicy -GroupName FinancialAdministrators -PolicyArn $accountPortalPolicy.Arn @session -Force
Register-IAMGroupPolicy -GroupName FinancialAdministrators -PolicyArn arn:aws:iam::aws:policy/job-function/Billing @session -Force

# Register policies on support access group
Register-IAMGroupPolicy -GroupName FinancialAdministrators -PolicyArn arn:aws:iam::aws:policy/job-function/SupportUser @session -Force
Register-IAMGroupPolicy -GroupName FinancialAdministrators -PolicyArn arn:aws:iam::aws:policy/AWSSupportAccess @session -Force

# Register policies on support role
Register-IAMRolePolicy -RoleName AWSSupportAccessRole -PolicyArn arn:aws:iam::aws:policy/AWSSupportAccess @session

Write-Output ("`t Policies successfully attached.")

# Stop the Transcript
Stop-Transcript

#True for success
return $true