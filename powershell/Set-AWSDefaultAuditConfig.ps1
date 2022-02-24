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

# Test if bucket exists
$account = (Get-STSCallerIdentity ).Account
$bucketName = ("config-bucket-{0}" -f $account)
$bucket = Get-S3Bucket -BucketName $bucketName 
$bucket | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders

if(!$bucket) {
    # Create bucket
    Write-Output ("`t Creating S3 bucket for config logs...")
    $bucket = New-S3Bucket -BucketName $bucketName -CannedACLName ([Amazon.S3.S3CannedACL]::BucketOwnerFullControl) 
    $bucket | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders

    # Let bucket creation take effect and propogate
    Write-Output ("`t Letting S3 bucket propogate...")
    Start-Sleep 5
    Write-Output ("`t Securing S3 bucket...")

    # Configure bucket policy
    Add-S3PublicAccessBlock -BucketName $bucketName -PublicAccessBlockConfiguration_BlockPublicAcl $true -PublicAccessBlockConfiguration_BlockPublicPolicy $true -PublicAccessBlockConfiguration_IgnorePublicAcl $true -PublicAccessBlockConfiguration_RestrictPublicBucket $true 
    Write-S3BucketPolicy -BucketName $bucketName -Policy (Get-content -Raw WSUPolicy_S3BucketConfig_Global.json).Replace("{accountid}", $account) 
    Write-S3BucketVersioning -BucketName $bucketName -VersioningConfig_Status Enabled 

    # Configure bucket encryption
    $s3EncryptionRule = New-Object -TypeName Amazon.S3.Model.ServerSideEncryptionRule
    $s3EncryptionDefault = New-Object -TypeName Amazon.S3.Model.ServerSideEncryptionByDefault
    $s3EncryptionDefault.ServerSideEncryptionAlgorithm = "AES256"
    $s3EncryptionRule.ServerSideEncryptionByDefault = $s3EncryptionDefault
    Set-S3BucketEncryption -BucketName $bucketName -ServerSideEncryptionConfiguration_ServerSideEncryptionRule $s3EncryptionRule 

    Write-Output ("`t S3 Bucket created.")
}

# Build Config recorder and channel
Write-Output ("`t Building config recorder and delivery channel...")
$cfgRecorder = Get-CFGConfigurationRecorder 
if(!$cfgRecorder) {
    $roleArn = ("arn:aws:iam::{0}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig" -f $account)
    $cfgRecorder = Write-CFGConfigurationRecorder -ConfigurationRecorderName default -RecordingGroup_AllSupported $true -RecordingGroup_IncludeGlobalResourceType $true -ConfigurationRecorder_RoleARN $roleArn 
    Start-Sleep 2
    
    $cfgRecorder = Get-CFGConfigurationRecorder -ConfigurationRecorderName default 
    $cfgRecorder | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

$cfgChannel = Get-CFGDeliveryChannel 
if(!$cfgChannel) {
    $cfgChannel = Write-CFGDeliveryChannel -DeliveryChannelName default -DeliveryChannel_S3BucketName $bucketName 
    $cfgChannel | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

# Start the recorder if it is stopped
$cfgRecorderStatus = Get-CFGConfigurationRecorderStatus 
if(!$cfgRecorderStatus.Recording) {
    Start-CFGConfigurationRecorder -ConfigurationRecorderName $cfgRecorder.Name 
}

# Set the config rules
Write-Output ("`t Building config compliance rules...")
$owner = [Amazon.ConfigService.Owner]::AWS
Import-Csv AWSConfigRules.csv | ForEach-Object {
    try {
        $cfgRule = Get-CFGConfigRule -ConfigRuleName $_.ConfigRuleName 
    } catch {
        $cfgRule = $false
    }

    if(!$cfgRule) {
        $cfgRule = @{
            'Source_Owner'              = $owner;
            'ConfigRule_ConfigRuleName' = $_.ConfigRuleName;
            'Source_SourceIdentifier'   = $_.ConfigRuleIdentity;
            'ConfigRule_Description'    = $_.Description;
            'ConfigRule_InputParameter' = $_.InputParameters.Replace("{accountid}", $account);
        }

        $cfgRule | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
        Write-CFGConfigRule @cfgRule 
    }
}

# Enable IAM analyzer
Write-Output ("`t Enabling IAM analyzer...")
$analyzers = Get-IAMAAAnalyzerList 
if($analyzers.Count -lt 1) {
    $analyzerName = ("ConsoleAnalyzer-{0}" -f (New-Guid).Guid.ToString())
    $analyzerType = [Amazon.AccessAnalyzer.Type]::ACCOUNT
    $analyzer = New-IAMAAAnalyzer -AnalyzerName $analyzerName -Type $analyzerType 
    $analyzer | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

# Enable Guard Duty
Write-Output ("`t Enabling Guard Duty...")
$guardDutyDetectors = Get-GDDetectorList 
if($guardDutyDetectors.Count -lt 1) {
    New-GDDetector -Enable $true 
}

# Enable Security Hub
Write-Output ("`t Enabling Security Hub...")
try {
    $hub = Get-SHUBHub 
} catch {
    Enable-SHUBSecurityHub 
    Start-Sleep 5
}

# Enable all available standards
$subscriptionRequest = New-Object Amazon.SecurityHub.Model.StandardsSubscriptionRequest
$availableStandards = Get-SHUBStandard 
foreach($standard in $availableStandards) {
    Start-Sleep 2
    $subscriptionRequest.StandardsArn = $standard.StandardsArn
    $hubResult = Enable-SHUBStandardsBatch -StandardsSubscriptionRequest $subscriptionRequest 
    $hubResult | Format-Table -Property @{Expression="            "},* -Autosize -Hidetableheaders
}

# Disable AWS SOC managed controls
Write-Output ("`t Disabling AWS SOC managed controls...")
Write-Output ("`t Waiting for objects to propogate...")
Start-Sleep 15
$enabledStandards = Get-SHUBEnabledStandard 
$awsStandardSubscriptionArn = $false
$cisStandardSubscriptionArn = $false
$pciStandardSubscriptionArn = $false
foreach($standard in $enabledStandards) {
    
    if($standard.StandardsArn -match "aws-foundational-security-best-practices") {
        $awsStandardSubscriptionArn = $standard.StandardsSubscriptionArn
        Write-Output("`t`t{0}" -f $awsStandardSubscriptionArn)
    }
    
    if($standard.StandardsArn -match "cis-aws-foundations-benchmark") {
        $cisStandardSubscriptionArn = $standard.StandardsSubscriptionArn
        Write-Output("`t`t{0}" -f $cisStandardSubscriptionArn)
    }

    if($standard.StandardsArn -match "pci-dss") {
        $pciStandardSubscriptionArn = $standard.StandardsSubscriptionArn
        Write-Output("`t`t{0}" -f $pciStandardSubscriptionArn)
    }
}

if($cisStandardSubscriptionArn) {
    $cisControls = Get-SHUBStandardsControl -StandardsSubscriptionArn $cisStandardSubscriptionArn 
    Import-Csv AWSCisControlsToDisable.csv | ForEach-Object {
        foreach($control in $cisControls) {
            if($_.ControlId -eq $control.ControlId -and $control.ControlStatus -eq "ENABLED") {
                Write-Output ("`t`t Disabling {0}" -f $_.ControlId)
                Start-Sleep 1
                Update-SHUBStandardsControl -StandardsControlArn $control.StandardsControlArn -ControlStatus DISABLED -DisabledReason $_.DisabledReason 
            }
        }
    }
} else {
    Write-Output ("`t AWS CIS Standard not enabled.")
}

if($pciStandardSubscriptionArn) {
    $pciControls = Get-SHUBStandardsControl -StandardsSubscriptionArn $pciStandardSubscriptionArn 
    Import-Csv AWSPciControlsToDisable.csv | ForEach-Object {
        foreach($control in $pciControls) {
            if($_.ControlId -eq $control.ControlId -and $control.ControlStatus -eq "ENABLED") {
                Write-Output ("`t`t Disabling {0}" -f $_.ControlId)
                Start-Sleep 1
                Update-SHUBStandardsControl -StandardsControlArn $control.StandardsControlArn -ControlStatus DISABLED -DisabledReason $_.DisabledReason 
            }
        }
    }
} else {
    Write-Output ("`t AWS CIS Standard not enabled.")
}

# Require EBS volumes to be encrypted
Enable-EC2EbsEncryptionByDefault 

Write-Output ("`t Compliance configurations complete.")

# Check if we are transcribing
if($transcribe) {
    Stop-Transcript
}

#True for success
return $true