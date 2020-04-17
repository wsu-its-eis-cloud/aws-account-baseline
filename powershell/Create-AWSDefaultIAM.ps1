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
$session = $null
$expression = ("`$session = `$global:{0}" -f $sessionName)
Invoke-Expression -Command $expression

# If the session is null, return false
if($session -eq $null) {
    Write-Output ("`t Failed to retrieve specified AWS session.")

    Stop-Transcript
    return $false
}

Write-Output ("`t Creating custom policy objects...")

# Create scoped us-west-2 admin policy
$usWestAdmin = New-IAMPolicy -PolicyName RegionUsWest2ScopedAdministrator -PolicyDocument (Get-content -Raw RegionUsWest2ScopedAdministrator.json) -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Create cloudwatch admin policy
$cloudwatchAdmin = New-IAMPolicy -PolicyName RegionUsEast1CloudWatchAdmin -PolicyDocument (Get-content -Raw RegionUsEast1CloudWatchAdmin.json) -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Create disable all region policy
$disableRegionsPolicy = New-IAMPolicy -PolicyName RegionDisableAll -PolicyDocument (Get-content -Raw RegionDisableAll.json) -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Create disable all region policy
$accountPortalPolicy = New-IAMPolicy -PolicyName AccountPortalFullAccess -PolicyDocument (Get-content -Raw AccountPortalFullAccess.json) -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Create admin group
$adminGroup = New-IAMGroup -GroupName Administrators -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Create financial admin group
$financialAdminGroup = New-IAMGroup -GroupName FinancialAdministrators -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Create support access group
$supportAccessGroup = New-IAMGroup -GroupName SupportAccess -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Retrieve account ID
$account = (Get-STSCallerIdentity -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken).Account

# Create aupport access role
$supportAccessRole = New-IAMRole -RoleName SupportAccess -AssumeRolePolicyDocument (Get-content -Raw SupportAccessRoleTrustPolicyDocument.json).Replace("{0}", $account) -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken

# Pause to allow custom objects to propogate
Write-Output ("`t Waiting for objects to propogate...")
Start-Sleep -Seconds 5

# Register policies on administrators group
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn $usWestAdmin.Arn -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn $cloudwatchAdmin.Arn -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn $disableRegionsPolicy.Arn -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn arn:aws:iam::aws:policy/IAMFullAccess -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn arn:aws:iam::aws:policy/AmazonS3FullAccess -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
Register-IAMGroupPolicy -GroupName Administrators -PolicyArn arn:aws:iam::aws:policy/job-function/Billing -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Register policies on financial administrators group
Register-IAMGroupPolicy -GroupName FinancialAdministrators -PolicyArn $accountPortalPolicy.Arn -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
Register-IAMGroupPolicy -GroupName FinancialAdministrators -PolicyArn arn:aws:iam::aws:policy/job-function/Billing -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Register policies on support access group
Register-IAMGroupPolicy -GroupName FinancialAdministrators -PolicyArn arn:aws:iam::aws:policy/job-function/SupportUser -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
Register-IAMGroupPolicy -GroupName FinancialAdministrators -PolicyArn arn:aws:iam::aws:policy/AWSSupportAccess -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

# Register policies on support access role
Register-IAMRolePolicy -RoleName SupportAccess -PolicyArn arn:aws:iam::aws:policy/AWSSupportAccess -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken

Write-Output ("`t Policies successfully attached.")

# Stop the Transcript
Stop-Transcript

#True for success
return $true