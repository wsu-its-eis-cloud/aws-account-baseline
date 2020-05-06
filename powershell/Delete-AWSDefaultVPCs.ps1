param(	
	[Alias("s")]
    [string] $sessionName = "awsDefaultSession",

    [Alias("f")]
    [switch] $force = $false,

    [Alias("t")]
    [switch] $transcribe = $false,
	
    [Alias("h")]
    [switch] $help = $false
)

if ($help) {
    Write-Output ("`t Deletes the default VPC's that are created on AWS account creation by deleting all VPC's without tags, and with the default CIDR block")
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
    Write-Output ("`t force")
    Write-Output ("`t     If set, suppresses delete confirmations.")
    Write-Output ("`t     Default: {0}" -f $force)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -force {1}" -f $MyInvocation.MyCommand.Name, $force)
    Write-Output ("`t     Example: .\{0}.ps1 -f {1}" -f $MyInvocation.MyCommand.Name, $force)
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

# If the force flag is not present, prompt session for confirmation
if(!$force) {
    Write-Output ("`t THIS OPERATION WILL DELETE ALL UNTAGGED VPCS IN YOUR ACCOUNT WITH A CIDR BLOCK OF 172.31.0.0/16")
    Write-Output ("`t`t Type 'DELETE' to confirm")
    $confirmation = Read-Host "`t`t Enter confirmation"

    if($confirmation -ne "DELETE") {
        Write-Output ("`t CONFIRMATION TEXT DOES NOT MATCH, ABORTING")
        return $false
    }
}

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

# Search each region for default VPC's to remove
$regions = Get-EC2Region @session
foreach($region in $regions) {

    $vpcs = Get-EC2Vpc -Region $region.RegionName @session
    foreach($vpc in $vpcs) {

        if ($vpc.Tags.Count -ne 0 -AND $vpc.CidrBlock.ToString() -ne "172.31.0.0/16") {
            Write-Output ("`t Skipping VPC: {0}." -f $vpc.VpcId)
        } else {
            # Build filters for IGW objects
            $filters = @()
            $filter = New-Object -TypeName Amazon.EC2.Model.Filter
            $filter.Name = "attachment.vpc-id"
            $filter.Values.Add($vpc.VpcId)
            $filters += $filter

            # Remove IGW's
            Write-Output ("`t")
            $igws = Get-EC2InternetGateway -Region $region.RegionName -Filter $filters @session
            foreach($igw in $igws) {

                Write-Output ("`t Dismounting IGW: {0}." -f $igw.InternetGatewayId)
                Dismount-EC2InternetGateway -Region $region.RegionName -InternetGatewayId $igw.InternetGatewayId -VpcId $vpc.VpcId  @session -Force

                Write-Output ("`t Removing IGW: {0}." -f $igw.InternetGatewayId)
                Remove-EC2InternetGateway -Region $region.RegionName -InternetGatewayId $igw.InternetGatewayId @session -Force
            }

            # Rebuild filters targeting subnet and routetable filters
            $filters = @()
            $filter = New-Object -TypeName Amazon.EC2.Model.Filter
            $filter.Name = "vpc-id"
            $filter.Values.Add($vpc.VpcId)
            $filters += $filter

            # Remove subnets
            $subnets = Get-EC2Subnet -Region $region.RegionName -Filter $filters @session
            foreach($subnet in $subnets) {
                Write-Output ("`t Removing subnet: {0}." -f $subnet.SubnetId)
                Remove-EC2Subnet -Region $region.RegionName -SubnetId $subnet.SubnetId @session -Force
            }

            # Remove VPC
            Write-Output ("`t Removing VPC: {0}." -f $vpc.VpcId)
            Remove-EC2Vpc -VpcId $vpc.VpcId -Region $region.RegionName @session -Force
        }
    }
}

Write-Output ("`t This house is clean.")

# Check if we are transcribing
if($transcribe) {
    Stop-Transcript
}

#True for success
return $true