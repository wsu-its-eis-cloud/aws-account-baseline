param(	
    [Alias("a")]
    [string] $accountName = "",

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
    Write-Output ("`t accountName")
    Write-Output ("`t     The name of the AWS account, e.g., its-aws-demo.  Used for setting signin-in alias.")
    Write-Output ("`t     Default: {0}" -f $sessionName)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -accountName {1}" -f $MyInvocation.MyCommand.Name, $accountName)
    Write-Output ("`t     Example: .\{0}.ps1 -a {1}" -f $MyInvocation.MyCommand.Name, $accountName)
    Write-Output ("`t ")
    Write-Output ("`t sessionName")
    Write-Output ("`t     The name of the global variable that stores the MFA validated AWS session.")
    Write-Output ("`t     Default: {0}" -f $sessionName)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -sessionName {1}" -f $MyInvocation.MyCommand.Name, $sessionName)
    Write-Output ("`t     Example: .\{0}.ps1 -s {1}" -f $MyInvocation.MyCommand.Name, $sessionName)

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

Write-Output ("`t Creating S3 bucket for config logs...")

# Create bucket
$account = (Get-STSCallerIdentity @session).Account
$bucketName = ("config-bucket-{0}" -f $account)
$bucket = New-S3Bucket -BucketName $bucketName -CannedACLName ([Amazon.S3.S3CannedACL]::BucketOwnerFullControl) @session

# Let bucket creation take effect and propogate
Write-Output ("`t Letting S3 bucket propogate...")
Start-Sleep 5
Write-Output ("`t Securing S3 bucket...")

# Configure bucket policy
Add-S3PublicAccessBlock -BucketName $bucketName -PublicAccessBlockConfiguration_BlockPublicAcl $true -PublicAccessBlockConfiguration_BlockPublicPolicy $true -PublicAccessBlockConfiguration_IgnorePublicAcl $true -PublicAccessBlockConfiguration_RestrictPublicBucket $true @session
Write-S3BucketPolicy -BucketName $bucketName -Policy (Get-content -Raw S3ConfigBucketPolicy.json).Replace("{accountid}", $account) @session
Write-S3BucketVersioning -BucketName $bucketName -VersioningConfig_Status Enabled @session

# Configure bucket encryption
$s3EncryptionRule = New-Object -TypeName Amazon.S3.Model.ServerSideEncryptionRule
$s3EncryptionDefault = New-Object -TypeName Amazon.S3.Model.ServerSideEncryptionByDefault
$s3EncryptionDefault.ServerSideEncryptionAlgorithm = "AES256"
$s3EncryptionRule.ServerSideEncryptionByDefault = $s3EncryptionDefault
Set-S3BucketEncryption -BucketName $bucketName -ServerSideEncryptionConfiguration_ServerSideEncryptionRule $s3EncryptionRule @session

Write-Output ("`t S3 Bucket created.")

# Stop the Transcript
Stop-Transcript

#True for success
return $true