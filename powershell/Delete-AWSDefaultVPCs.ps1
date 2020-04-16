param(	
	[Alias("s")]
    [string] $sessionName = "awsDefaultSession",

    [Alias("f")]
    [switch] $force = $false,
	
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

    return $false
}

# navigate to library root
cd $PSScriptRoot

# load necessary modules
.\import-required-modules.ps1

# Start the transcript
$transcriptName = ("{0}-{1}.transcript" -f $MyInvocation.MyCommand.Name, [DateTimeOffset]::Now.ToUnixTimeSeconds())
Start-Transcript -Path $transcriptName

# If the force flag is not present, prompt session for confirmation
if(!$force) {
    Write-Output ("`t THIS OPERATION WILL DELETE ALL UNNAMED VPCS IN YOUR ACCOUNT")
    #Write-Host ("`t THIS OPERATION WILL DELETE ALL UNNAMED VPCS IN YOUR ACCOUNT")

    Write-Output ("`t TYPE 'DELETE' TO CONFIRM")
    #Write-Host ("`t TYPE 'DELETE' TO CONFIRM")

    $confirmation = Read-Host "`t ENTER DELETE"

    if($confirmation -ne "DELETE") {
        Write-Output ("`t CONFIRMATION TEXT DOES NOT MATCH, ABORTING")
        #Write-Host ("`t CONFIRMATION TEXT DOES NOT MATCH, ABORTING")

        return $false
    }
}

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

# Search each region for default VPC's to remove
$regions = Get-EC2Region -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken
foreach($region in $regions) {

    $vpcs = Get-EC2Vpc -Region $region.RegionName -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken
    foreach($vpc in $vpcs) {

        if ($vpc.Tags.Count -ne 0 -AND $vpc.CidrBlock.ToString() -ne "172.31.0.0/16") {
            Write-Output ("`t Skipping VPC: {0}." -f $vpc.VpcId)
            continue;
        }
        
        # Build filters for IGW objects
        $filters = @()
        $filter = New-Object -TypeName Amazon.EC2.Model.Filter
        $filter.Name = "attachment.vpc-id"
        $filter.Values.Add($vpc.VpcId)
        $filters += $filter

        # Remove IGW's
        Write-Output ("`t")
        $igws = Get-EC2InternetGateway -Region $region.RegionName -Filter $filters -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken
        foreach($igw in $igws) {

            Write-Output ("`t Dismounting IGW: {0}." -f $igw.InternetGatewayId)
            Dismount-EC2InternetGateway -Region $region.RegionName -InternetGatewayId $igw.InternetGatewayId -VpcId $vpc.VpcId  -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force

            Write-Output ("`t Removing IGW: {0}." -f $igw.InternetGatewayId)
            Remove-EC2InternetGateway -Region $region.RegionName -InternetGatewayId $igw.InternetGatewayId -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
        }

        # Rebuild filters targeting subnet and routetable filters
        $filters = @()
        $filter = New-Object -TypeName Amazon.EC2.Model.Filter
        $filter.Name = "vpc-id"
        $filter.Values.Add($vpc.VpcId)
        $filters += $filter

        # Remove subnets
        $subnets = Get-EC2Subnet -Region $region.RegionName -Filter $filters -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken
        foreach($subnet in $subnets) {
            Write-Output ("`t Removing subnet: {0}." -f $subnet.SubnetId)
            Remove-EC2Subnet -Region $region.RegionName -SubnetId $subnet.SubnetId -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
        }

        # Remove VPC
        Write-Output ("`t Removing VPC: {0}." -f $vpc.VpcId)
        Remove-EC2Vpc -VpcId $vpc.VpcId -Region $region.RegionName -AccessKey $session.AccessKeyId -SecretKey $session.SecretAccessKey -SessionToken $session.SessionToken -Force
    }
}

Write-Output ("`t")
Write-Output ("`t")
Write-Output ("`t This house is clean.")

# Stop the Transcript
Stop-Transcript

#True for success
return $true