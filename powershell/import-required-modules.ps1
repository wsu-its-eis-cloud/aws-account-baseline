# Check for common module
if (Get-Module -ListAvailable -Name AWS.Tools.Common) {
    Import-Module AWS.Tools.Common
} 
else {
    Write-Host "Module Import-Module AWS.Tools.Common has not been installed.  Please run this libraries setup script."
    return;
}

# Check for EC2 module
if (Get-Module -ListAvailable -Name AWS.Tools.EC2) {
    Import-Module AWS.Tools.Common
} 
else {
    Write-Host "Module Import-Module AWS.Tools.Common has not been installed.  Please run this libraries setup script."
    return;
}

# Check for EC2 module
if (Get-Module -ListAvailable -Name AWS.Tools.S3) {
    Import-Module AWS.Tools.S3
} 
else {
    Write-Host "Module Import-Module AWS.Tools.S3 has not been installed.  Please run this libraries setup script."
    return;
}

# Check for EC2 module
if (Get-Module -ListAvailable -Name AWS.Tools.ConfigService) {
    Import-Module AWS.Tools.ConfigService
} 
else {
    Write-Host "Module Import-Module AWS.Tools.ConfigService has not been installed.  Please run this libraries setup script."
    return;
}