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

# Check for S3 module
if (Get-Module -ListAvailable -Name AWS.Tools.S3) {
    Import-Module AWS.Tools.S3
} 
else {
    Write-Host "Module Import-Module AWS.Tools.S3 has not been installed.  Please run this libraries setup script."
    return;
}

# Check for ConfigService module
if (Get-Module -ListAvailable -Name AWS.Tools.ConfigService) {
    Import-Module AWS.Tools.ConfigService
} 
else {
    Write-Host "Module Import-Module AWS.Tools.ConfigService has not been installed.  Please run this libraries setup script."
    return;
}

# Check for AccessAnalyzer module
if (Get-Module -ListAvailable -Name AWS.Tools.AccessAnalyzer) {
    Import-Module AWS.Tools.AccessAnalyzer
} 
else {
    Write-Host "Module Import-Module AWS.Tools.AccessAnalyzer has not been installed.  Please run this libraries setup script."
    return;
}

# Check for GuardDuty module
if (Get-Module -ListAvailable -Name AWS.Tools.GuardDuty) {
    Import-Module AWS.Tools.GuardDuty
} 
else {
    Write-Host "Module Import-Module AWS.Tools.GuardDuty has not been installed.  Please run this libraries setup script."
    return;
}

# Check for SecurityHub module
if (Get-Module -ListAvailable -Name AWS.Tools.SecurityHub) {
    Import-Module AWS.Tools.SecurityHub
} 
else {
    Write-Host "Module Import-Module AWS.Tools.SecurityHub has not been installed.  Please run this libraries setup script."
    return;
}