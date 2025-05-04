# Get Active Users
Write-Output "Running script..."
# header for active users 
Write-Output "Active Users"
# currently logged in users, extracts and displays username (Changed it so it gathers all locl users and then it will give us the active users)
Get-LocalUser | Where-Object {$_.Enabled -eq $true } | Select-Object Name 
# Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName

# Get-WmiObject - gets instances of windows management instrumentation classes or information about the available classes
# Win32_ComputerSystem represents a computer system running Windows
#

# Get Installed Software & Versions
Write-Output "`nInstalled Software"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize

# Check Missing Security Patches
Write-Output "`nMissing Security Patches"
Get-WmiObject -Query "Select * from Win32_QuickFixEngineering" | 
Select-Object HotFixID, InstalledOn, Description | Format-Table -AutoSize


# Define paths
$sysinternalsPath = "C:\Tools\Sysinternals"
$nirsoftPath = "C:\Tools\Nirsoft"
$sysinternalsZipUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$sysinternalsZipFile = "$env:TEMP\SysinternalsSuite.zip"
$usbDeviewUrl = "https://www.nirsoft.net/utils/usbdeview-x64.zip"
$usbDeviewZipFile = "$env:TEMP\usbdeview.zip"

# Function to check and download Sysinternals if missing
function Ensure-Sysinternals {
    if (-not (Test-Path $sysinternalsPath)) {
        Write-Host "Sysinternals not found. Downloading..."
        
        # Download Sysinternals Suite
        Invoke-WebRequest -Uri $sysinternalsZipUrl -OutFile $sysinternalsZipFile

        # Extract to C:\Tools\Sysinternals
        Expand-Archive -Path $sysinternalsZipFile -DestinationPath $sysinternalsPath -Force
        
        Write-Host "Sysinternals installed at $sysinternalsPath."
    } else {
        Write-Host "Sysinternals is already installed."
    }
}

# Function to check and download USBDeview if missing
function Ensure-USBDeview {
    if (-not (Test-Path "$nirsoftPath\USBDeview.exe")) {
        Write-Host "USBDeview not found. Downloading..."

        # Create directory if it doesn't exist
        if (-not (Test-Path $nirsoftPath)) {
            New-Item -ItemType Directory -Path $nirsoftPath | Out-Null
        }

        # Download USBDeview
        Invoke-WebRequest -Uri $usbDeviewUrl -OutFile $usbDeviewZipFile

        # Extract USBDeview to NirSoft folder
        Expand-Archive -Path $usbDeviewZipFile -DestinationPath $nirsoftPath -Force

        Write-Host "USBDeview installed at $nirsoftPath."
    } else {
        Write-Host "USBDeview is already installed."
    }
}

# Ensure Sysinternals and USBDeview are installed
Ensure-Sysinternals
Ensure-USBDeview

# Unblock downloaded executables if needed
Unblock-File -Path "$sysinternalsPath\Autoruns64.exe"
Unblock-File -Path "$nirsoftPath\USBDeview.exe"

# Run Autoruns if found
if (Test-Path "$sysinternalsPath\Autoruns64.exe") {
    Start-Process "$sysinternalsPath\Autoruns64.exe" -ArgumentList "/accepteula /xml autoruns.xml" -NoNewWindow -Wait
    Write-Host "Autoruns output saved as autoruns.xml"
} else {
    Write-Host "Error: Autoruns64.exe not found!"
}

# Run USBDeview if found
if (Test-Path "$nirsoftPath\USBDeview.exe") {
    Start-Process "$nirsoftPath\USBDeview.exe" -ArgumentList "/scomma usb_history.csv" -NoNewWindow -Wait
    Write-Host "USB history saved as usb_history.csv"
} else {
    Write-Host "Error: USBDeview.exe not found!"
    }