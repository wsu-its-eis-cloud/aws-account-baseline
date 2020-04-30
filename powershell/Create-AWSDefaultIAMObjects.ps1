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
$policies = @()
$policyList = Get-IAMPolicyList -Scope Local @session
Import-Csv WSUIamPolicies.csv | ForEach-Object {
    $policy = $_

    if(($policyList | Where-Object {$_.PolicyName -eq $policy.PolicyName}).Count -eq 0) {
        $temp = New-IAMPolicy -PolicyName $policy.PolicyName -PolicyDocument (Get-content -Raw $policy.PolicyDocument) @session -Force
        $temp | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
        $policies = $policies + $temp
    }
}

# Create groups
# Gets the list of groups
$groups = @()
$groupList = Get-IAMGroupList @session
Import-Csv WSUIamGroups.csv | ForEach-Object {
    $group = $_

    if(($groupList | Where-Object {$_.GroupName -eq $group.GroupName}).Count -eq 0) {
        $temp = New-IAMGroup -GroupName $group.GroupName @session -Force
        $temp | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
        $groups = $groups + $temp
    }
}

# Create service-linked roles
# Gets the list of roles
$roles = @()
$roleList = Get-IAMRoleList @session
Import-Csv WSUIamRoles.csv | ForEach-Object {
    $role = $_

    if(($roleList | Where-Object {$_.RoleName -eq $role.RoleName}).Count -eq 0) {
        $temp = New-IAMRole -RoleName $role.RoleName -AssumeRolePolicyDocument (Get-content -Raw $role.AssumeRolePolicyDocument).Replace("{accountid}", $accountid) @session
        $temp | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
        $roles = $roles + $temp
    }
}

Import-Csv WSUIamServiceLinkedRoles.csv | ForEach-Object {
    $role = $_

    if(($roleList | Where-Object {$_.RoleName -eq $role.RoleName}).Count -eq 0) {
        $temp = New-IAMServiceLinkedRole -AWSServiceName $role.AWSServiceName @session
        $temp | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
        $roles = $roles + $temp
    }
}


# Pause to allow custom objects to propogate
Write-Output ("`t Waiting for objects to propogate...")
Start-Sleep -Seconds 5

# Register group policies
Import-Csv WSUIamGroupPolicy.csv | ForEach-Object {
    $groupPolicy = $_
    foreach($group in $groups) {
        foreach($policy in $policies) {
            if($groupPolicy.GroupName -eq $group.GroupName -and $groupPolicy.PolicyName -eq $policy.PolicyName) {
                Register-IAMGroupPolicy -GroupName $group.GroupName -PolicyArn $policy.Arn @session -Force
            }
        }
    }
}

# Register role policies
Import-Csv WSUIamRolePolicy.csv | ForEach-Object {
    $rolePolicy = $_
    foreach($role in $roles) {
        foreach($policy in $policies) {
            if($rolePolicy.RoleName -eq $role.RoleName -and $rolePolicy.PolicyName -eq $policy.PolicyName) {
                Register-IAMRolePolicy -RoleName $rolePolicy.RoleName -PolicyArn $rolePolicy.PolicyArn @session
            }
        }
    }
}

Write-Output ("`t Policies successfully attached.")

# Check if we are transcribing
if($transcribe) {
    Stop-Transcript
}

#True for success
return $true