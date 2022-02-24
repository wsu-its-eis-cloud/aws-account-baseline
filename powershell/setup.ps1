#Requires -RunAsAdministrator
param(
    [Alias("f")]
    [switch] $force = $false,

    [Alias("h")]
    [switch] $help = $false
)

if ($help) {
	Write-Output ("Installs and manages packages used by this library.")
	Write-Output ("Prerequisites: Powershell")
	Write-Output ("")
	Write-Output ("Parameters:")
	Write-Output ("")
	Write-Output ("force")
	Write-Output ("    Force the reinstallation and upgrade of modules.")
	Write-Output ("    Default: {0}" -f $force)
    Write-Output ("    Alias: f")
	Write-Output ("    Example: ./setup.ps1 -force")
    Write-Output ("    Example: ./setup.ps1 -f")
	return
}

# Trust the PSGallery
if((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
    Write-Output "Setting PSGallery to trusted."
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
}

# Check if we are running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Output "Please re-run as administrator."
    return
}

# Track whether any modules are installed
$changesMade = $false

# Check for NuGet package provider
if (!(Get-PackageProvider -Name "NuGet") -or $force) {
    if($force) {
        Install-PackageProvider -Name NuGet -Force
    } else {
        Install-PackageProvider -Name NuGet
    }

    $changesMade = $true
}

# Check for AWS.Tools - First dependency
if (!(Get-Module -ListAvailable -Name AWS.Tools.Installer) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.Installer -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.Installer
    }

    $changesMade = $true
}

# Update modules and cleanup old versions to minimize warnings during installation of any missing modules.
Update-AWSToolsModule -CleanUp -AllowClobber -Force -Confirm

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.Common) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.Common -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.Common
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.EC2) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.EC2 -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.EC2
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.S3) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.S3 -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.S3
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.ConfigService) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.ConfigService -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.ConfigService
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.AccessAnalyzer) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.AccessAnalyzer -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.AccessAnalyzer
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.GuardDuty) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.GuardDuty -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.GuardDuty
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.SecurityHub) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.SecurityHub -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.SecurityHub
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.Lambda) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.Lambda -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.Lambda
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.CloudWatch) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.CloudWatch -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.CloudWatch
    }

    $changesMade = $true
}

# Check for modules required by this library
if (!(Get-Module -ListAvailable -Name AWS.Tools.IdentityManagement) -or $force) {
    if($force) {
        Install-Module -Name AWS.Tools.IdentityManagement -AllowClobber -Force
    } else {
        Install-Module -Name AWS.Tools.IdentityManagement
    }

    $changesMade = $true
}


if($changesMade) {
    Write-Output "Modules successfully installed and updated."
}else {
    Write-Output "No changes detected."
}