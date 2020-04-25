param(	
	[Alias("s")]
    [string] $sessionName = "awsDefaultSession",

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
    Write-Output ("`t sessionName")
    Write-Output ("`t     The name of the global variable that stores the MFA validated AWS session.")
    Write-Output ("`t     Default: {0}" -f $sessionName)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -sessionName {1}" -f $MyInvocation.MyCommand.Name, $sessionName)
    Write-Output ("`t     Example: .\{0}.ps1 -s {1}" -f $MyInvocation.MyCommand.Name, $sessionName)
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

# Retrieve specified AWS STS session
$globalSession = $null
$expression = ("`$globalSession = `$global:{0}" -f $sessionName)
Invoke-Expression -Command $expression

# If the session is null, return false
if($globalSession -eq $null) {
    Write-Output ("`t Failed to retrieve specified AWS session.")
    if($transcribe) {
        Stop-Transcript
    }

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
$accountid = (Get-STSCallerIdentity @session).Account

# Create WSU policies
# Get the list of existing policies
$policyList = Get-IAMPolicyList -Scope Local @session
if(($policyList | Where-Object {$_.PolicyName -eq "WsuRegionUsWest2ScopedAdministrator"}).Count -eq 0) {
    $usWestAdmin = New-IAMPolicy -PolicyName WsuRegionUsWest2ScopedAdministrator -PolicyDocument (Get-content -Raw WsuRegionUsWest2ScopedAdministrator.json) @session -Force
    $usWestAdmin | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

if(($policyList | Where-Object {$_.PolicyName -eq "WsuRegionUsEast1CloudWatchAdmin"}).Count -eq 0) {
    $cloudwatchAdmin = New-IAMPolicy -PolicyName WsuRegionUsEast1CloudWatchAdmin -PolicyDocument (Get-content -Raw WsuRegionUsEast1CloudWatchAdmin.json) @session -Force
    $cloudwatchAdmin | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

if(($policyList | Where-Object {$_.PolicyName -eq "WsuRegionDisableAll"}).Count -eq 0) {
    $disableRegionsPolicy = New-IAMPolicy -PolicyName WsuRegionDisableAll -PolicyDocument (Get-content -Raw WsuRegionDisableAll.json) @session -Force
    $disableRegionsPolicy | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

if(($policyList | Where-Object {$_.PolicyName -eq "WsuAccountPortalFullAccess"}).Count -eq 0) {
    $accountPortalPolicy = New-IAMPolicy -PolicyName WsuAccountPortalFullAccess -PolicyDocument (Get-content -Raw WsuAccountPortalFullAccess.json) @session -Force
    $accountPortalPolicy | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

# Create groups
# Gets the list of groups
$groupList = Get-IAMGroupList @session

if(($groupList | Where-Object {$_.GroupName -eq "Administrators"}).Count -eq 0) {
    $adminGroup = New-IAMGroup -GroupName Administrators @session -Force
    $adminGroup | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

if(($groupList | Where-Object {$_.GroupName -eq "FinancialAdministrators"}).Count -eq 0) {
    $financialAdminGroup = New-IAMGroup -GroupName FinancialAdministrators @session -Force
    $financialAdminGroup | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

if(($groupList | Where-Object {$_.GroupName -eq "Administrators"}).Count -eq 0) {
    $supportAccessGroup = New-IAMGroup -GroupName SupportAccess @session -Force
    $supportAccessGroup | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

# Create service-linked roles
# Gets the list of roles
$roleList = Get-IAMRoleList @session

if(($roleList | Where-Object {$_.RoleName -eq "AWSServiceRoleForAccessAnalyzer"}).Count -eq 0) {
    $accessAnalyzerRole = New-IAMServiceLinkedRole -AWSServiceName access-analyzer.amazonaws.com @session
    $accessAnalyzerRole | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

if(($roleList | Where-Object {$_.RoleName -eq "AWSServiceRoleForAmazonGuardDuty"}).Count -eq 0) {
    $guardDutyRole = New-IAMServiceLinkedRole -AWSServiceName guardduty.amazonaws.com @session
    $guardDutyRole | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

if(($roleList | Where-Object {$_.RoleName -eq "AWSServiceRoleForConfig"}).Count -eq 0) {
    $configServiceRole = New-IAMServiceLinkedRole -AWSServiceName config.amazonaws.com @session
    $configServiceRole | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

if(($roleList | Where-Object {$_.RoleName -eq "AWSServiceRoleForSecurityHub"}).Count -eq 0) {
    $securityHubRole = New-IAMServiceLinkedRole -AWSServiceName securityhub.amazonaws.com @session
    $securityHubRole | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

# Create support access role
if(($roleList | Where-Object {$_.RoleName -eq "AWSSupportAccessRole"}).Count -eq 0) {
    $supportAccessRole = New-IAMRole -RoleName AWSSupportAccessRole -AssumeRolePolicyDocument (Get-content -Raw AWSSupportAccessRole-TrustPolicyDocument.json).Replace("{accountid}", $accountid) @session
    $supportAccessRole | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

# Pause to allow custom objects to propogate
Write-Output ("`t Waiting for objects to propogate...")
Start-Sleep -Seconds 5

# Refresh our policy list to reflect newly created policies (needed for non-destructive re-run)
$policyList = Get-IAMPolicyList -Scope Local @session
$policyList | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
$usWestAdmin = ($policyList | Where-Object {$_.PolicyName -eq "WsuRegionUsWest2ScopedAdministrator"})[0]
$cloudwatchAdmin = ($policyList | Where-Object {$_.PolicyName -eq "WsuRegionUsEast1CloudWatchAdmin"})[0]
$disableRegionsPolicy = ($policyList | Where-Object {$_.PolicyName -eq "WsuRegionDisableAll"})[0]
$accountPortalPolicy = ($policyList | Where-Object {$_.PolicyName -eq "WsuAccountPortalFullAccess"})[0]

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

# Check if we are transcribing
if($transcribe) {
    Stop-Transcript
}

#True for success
return $true