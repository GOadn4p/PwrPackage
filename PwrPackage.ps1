############# Set the global error action preference to SilentlyContinue #############

$ErrorActionPreference = "SilentlyContinue"

############################# PROGRESS BAR #############################

# Total number of artifacts being gathered
$totalArtifacts = 32

# Initialize the progress counter
$progressCounter = 0

# Function to update the progress bar (POWERSHELL READY PREFERED)
function Update-ProgressBar {
    param (
        [int]$current,
        [int]$total
    )

    # Calculate the percentage completion
    $percentage = ($current / $total) * 100

    # Update the progress bar
    Write-Progress -Activity "Gathering Artifacts" -Status "Processing..." -PercentComplete $percentage
}

############################# LOG EVIDENCE COLLECTION FUNCTION #############################

function Log-TaskCompletion {
    param (
        [string]$taskName
    )

    # Get the current date and time
    $currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Create the log entry in a table format
    $logEntry = "{0,-20} {1}" -f $currentDateTime, $taskName

    # Write the log entry to the task completion log file
    $logEntry | Out-File -FilePath $evidenceCollectionLogFilePath -Append
}

############################# PRINT TASK STATUS FUNCTIONS #############################

# Function to print task starting message
function Print-TaskStart {
    param (
        [string]$taskName
    )

    Write-Host "Current Task: $taskName" -ForegroundColor Green
}


############################# BANNER & FOOTER #############################

$bannerText = @"
.--------------------------------------------------.
|   _____           _____         _                |
|  |  _  |_ _ _ ___|  _  | __ ___| |_  __ ___ ___  |
|  |   __| | | |  _|   __||. |  _| '_||. | . | -_| |
|  |__|  |_____|_| |__|  |___|___|_|_|___|_  |___| |
|                                        |___|     |
|            --------------------------            |
|               Created by: GOadn4p                |
|                   •@GOadn4p                      |
|                   •GOadn4p.blog                  |
'--------------------------------------------------'
"@

$footerText = @"
      |\__/,|   (`\ 
    _.|o o  |_   ) )
---(((---(((---------
"@


############################# ESTABLISH FOLDER STRUCTURE #############################

# Define desktop path
$desktopPath = [Environment]::GetFolderPath("Desktop")

# Define the investigation folder path
$investigationFolderPath = Join-Path -Path $desktopPath -Childpath "Investigation Package"

# Create the Investigation Files folder
New-Item -Path $investigationFolderPath -ItemType Directory -Force | Out-Null

#Create subfolders within the Investigation Files folder
$processListingFolder = Join-Path -Path $investigationFolderPath -ChildPath "01. Process"
$networkCommunicationsFolder = Join-Path -Path $investigationFolderPath -ChildPath "02. Network"
$registryFolder = Join-Path -Path $investigationFolderPath -ChildPath "03. Registry"
$collectedFilesFolder = Join-Path -Path $investigationFolderPath -ChildPath "04. File Collection"
$scheduledTaskFolder = Join-Path -Path $investigationFolderPath -ChildPath "05. Task Scheduler"
$prefetchFolder = Join-Path -Path $investigationFolderPath -ChildPath "06. Prefetch"
$browserHistoryFolder = Join-Path -Path $investigationFolderPath -ChildPath "07. Browser"
$antivirusFolder = Join-Path -Path $investigationFolderPath -ChildPath "08. Anti Virus"
$eventLogsFolder = Join-Path -Path $investigationFolderPath -ChildPath "09. Event Logs"


$tempFolder = Join-Path -Path $collectedFilesFolder -ChildPath "Temp_Files"

$chromeBrowserHistoryFolder = Join-Path -Path $browserHistoryFolder -ChildPath "Chrome"
$edgeBrowserHistoryFolder = Join-Path -Path $browserHistoryFolder -ChildPath "Edge"
$firefoxBrowserHistoryFolder = Join-Path -Path $browserHistoryFolder -ChildPath "FireFox"

$quarantineFolder = Join-Path -Path $antivirusFolder -ChildPath "Defender Quarantine"

# Create the subfolders
$folders = $processListingFolder, $networkCommunicationsFolder, $registryFolder, $eventLogsFolder, $scheduledTaskFolder, $prefetchFolder
$folders += $collectedFilesFolder, $tempFolder
$folders += $antivirusFolder, $quarantineFolder
$folders += $browserHistoryFolder, $chromeBrowserHistoryFolder, $edgeBrowserHistoryFolder, $firefoxBrowserHistoryFolder
$folders | ForEach-Object {
    New-Item -Path $_ -ItemType Directory -Force | Out-Null
}

### Zip Folder Location###

# Define the path to the final zip file
$zipFileName = "InvestigationPackage.zip"
$zipFilePath = Join-Path $desktopPath $zipFileName


############################# ESTABLISH OUTPUT FILE STRUCTURE #############################

# Output file paths for each artifact category
$processListingFilePath = Join-Path -Path $processListingFolder -ChildPath "Process_Listing.txt"
$networkCommunicationsFilePath = Join-Path -Path $networkCommunicationsFolder -ChildPath "Netstat.txt"
$scheduledTaskFilePath = Join-Path -Path $scheduledTaskFolder -ChildPath "Scheduled_Tasks.txt"
$registryFilePath = Join-Path -Path $registryFolder -ChildPath "Registry.txt"
$runCurrentUserFilePath = Join-Path -Path $registryFolder -ChildPath "Run_CurrentUser.txt"
$runOnceCurrentUserFilePath = Join-Path -Path $registryFolder -ChildPath "RunOnce_CurrentUser.txt"
$runLocalMachineFilePath = Join-Path -Path $registryFolder -ChildPath "Run_LocalMachine.txt"
$runOnceLocalMachineFilePath = Join-Path -Path $registryFolder -ChildPath "RunOnce_LocalMachine.txt"
$userShellFoldersCurrentUserFilePath = Join-Path -Path $registryFolder -ChildPath "UserShellFolders_CurrentUser.txt"
$shellFoldersCurrentUserFilePath = Join-Path -Path $registryFolder -ChildPath "ShellFolders_CurrentUser.txt"
$shellFoldersLocalMachineFilePath = Join-Path -Path $registryFolder -ChildPath "ShellFolders_LocalMachine.txt"
$userShellFoldersLocalMachineFilePath = Join-Path -Path $registryFolder -ChildPath "UserShellFolders_LocalMachine.txt"
$runServicesOnceLocalMachineFilePath = Join-Path -Path $registryFolder -ChildPath "RunServicesOnce_LocalMachine.txt"
$runServicesOnceCurrentUserFilePath = Join-Path -Path $registryFolder -ChildPath "RunServicesOnce_CurrentUser.txt"
$runServicesLocalMachineFilePath = Join-Path -Path $registryFolder -ChildPath "RunServices_LocalMachine.txt"
$runServicesCurrentUserFilePath = Join-Path -Path $registryFolder -ChildPath "RunServices_CurrentUser.txt"
$systemEventLogFilePath = Join-Path -Path $eventLogsFolder -ChildPath "System_Event_Log.txt"
$securityEventLogFilePath = Join-Path -Path $eventLogsFolder -ChildPath "Security_Event_Log.txt"
$applicationEventLogFilePath = Join-Path -Path $eventLogsFolder -ChildPath "Application_Event_Log.txt"
$powerShellEventLogFilePath = Join-Path -Path $eventLogsFolder -ChildPath "Windows_PowerShell.txt"
$powerShellOperationalEventLogFilePath = Join-Path -Path $eventLogsFolder -ChildPath "Windows_PowerShell_Operational.txt"
$ChromebrowserHistoryRawFilePath = Join-Path -Path $chromeBrowserHistoryFolder -ChildPath "Chrome_Browser_History_Raw.txt"
$ChromebrowserHistoryParsedFilePath = Join-Path -Path $chromeBrowserHistoryFolder -ChildPath "Chrome_Browser_History_Parsed.txt"
$EdgebrowserHistoryParsedFilePath = Join-Path -Path $edgeBrowserHistoryFolder -ChildPath "EDGE_Browser_History_Parsed.txt"
$EdgebrowserHistoryRawFilePath = Join-Path -Path $edgeBrowserHistoryFolder -ChildPath "EDGE_Browser_History_Raw.txt"
$FireFoxbrowserHistoryRawFilePath = Join-Path -Path $firefoxBrowserHistoryFolder -ChildPath "FireFox_Browser_History_Raw.txt"
$FireFoxbrowserHistoryParsedFilePath = Join-Path -Path $firefoxBrowserHistoryFolder -ChildPath "FireFox_Browser_History_Parsed.txt"
$prefetchFilesFolder = Join-Path -Path $prefetchFolder -ChildPath "Prefetch_Files"
$tempFilesMetadataFilePath = Join-Path -Path $tempFolder -ChildPath "Temp_Files_Metadata.csv"
$tempFilesMetadataTableFilePath = Join-Path -Path $tempFolder -ChildPath "Temp_Files_Metadata_Table.txt"
$tempFilesMetadataTableSignaturePath = Join-Path -Path $tempFolder -ChildPath "signatures.csv"
$antivirusLogFilePath = Join-Path -Path $antivirusFolder -ChildPath "AntiVirus_Info.txt"
$antivirusCSVLogFilePath = Join-Path -Path $antivirusFolder -ChildPath "AntiVirus_Info.csv"

$evidenceCollectionLogFilePath = Join-Path -Path $investigationFolderPath -ChildPath "Evidence_Collection_Log.txt"


## Add a dummy progress update to ensure the progress bar is created
Write-Progress -Activity "Preparing tasks" -Status "Starting..." -PercentComplete 0

# Add a delay before starting the first task to allow the progress bar to appear
Start-Sleep -Seconds 1

# Print 3 blank lines
for ($i = 1; $i -le 3; $i++) {
    Write-Host ""
}

########### BANNER ###########
Write-Host $bannerText

# Print 1 blank lines
for ($i = 1; $i -le 1; $i++) {
    Write-Host ""
}


# Add a delay before starting the first task to allow the progress bar to appear
Start-Sleep -Seconds 1

############################# ARTIFACT GATHERANCE #############################

############# 01. Process Listing #############

# Gather artifacts and store the output in the respective files
Print-TaskStart -taskName "Process Listing Collection"
Get-Process | Out-File -FilePath $processListingFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Log-TaskCompletion -taskName "Process Listing Collection"


############# 02. Network Traffic #############

#Netstat
Print-TaskStart -taskName "Network Communications Collection"
netstat -a | Out-File -FilePath $networkCommunicationsFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Log-TaskCompletion -taskName "Network Communications Collection"


############# 03. REGISTRY #############

# Gather registry entries
Print-TaskStart -taskName "Registry Entry Collection"

# Gather registry entries

Write-Output "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue | Out-File -FilePath $registryFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Write-Output "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"

Write-Output "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$runCurrentUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path $runCurrentUserPath -ErrorAction SilentlyContinue | Out-File -FilePath $runCurrentUserFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$runOnceCurrentUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty -Path $runOnceCurrentUserPath -ErrorAction SilentlyContinue | Out-File -FilePath $runOnceCurrentUserFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$runLocalMachinePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path $runLocalMachinePath -ErrorAction SilentlyContinue | Out-File -FilePath $runLocalMachineFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$runOnceLocalMachinePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty -Path $runOnceLocalMachinePath -ErrorAction SilentlyContinue | Out-File -FilePath $runOnceLocalMachineFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$userShellFoldersCurrentUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
Get-ItemProperty -Path $userShellFoldersCurrentUserPath -ErrorAction SilentlyContinue | Out-File -FilePath $userShellFoldersCurrentUserFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
$shellFoldersCurrentUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
Get-ItemProperty -Path $shellFoldersCurrentUserPath -ErrorAction SilentlyContinue | Out-File -FilePath $shellFoldersCurrentUserFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
$shellFoldersLocalMachinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
Get-ItemProperty -Path $shellFoldersLocalMachinePath -ErrorAction SilentlyContinue | Out-File -FilePath $shellFoldersLocalMachineFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$userShellFoldersLocalMachinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
Get-ItemProperty -Path $userShellFoldersLocalMachinePath -ErrorAction SilentlyContinue | Out-File -FilePath $userShellFoldersLocalMachineFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
$runServicesOnceLocalMachinePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
Get-ItemProperty -Path $runServicesOnceLocalMachinePath -ErrorAction SilentlyContinue | Out-File -FilePath $runServicesOnceLocalMachineFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
$runServicesOnceCurrentUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
Get-ItemProperty -Path $runServicesOnceCurrentUserPath -ErrorAction SilentlyContinue | Out-File -FilePath $runServicesOnceCurrentUserFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
$runServicesLocalMachinePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
Get-ItemProperty -Path $runServicesLocalMachinePath -ErrorAction SilentlyContinue | Out-File -FilePath $runServicesLocalMachineFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Write-Output "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices"
$runServicesCurrentUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices"
Get-ItemProperty -Path $runServicesCurrentUserPath -ErrorAction SilentlyContinue | Out-File -FilePath $runServicesCurrentUserFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Log-TaskCompletion -taskName "Registry Entry Collection"

############# 04. File Collection #############

Print-TaskStart -taskName "Windows Directories File Collection"

############# TEMP FOLDER DATA #############

Write-Output "Temp Directory Locations"
# Define the root directory where the search should start

$rootDirectory = "C:\"

$tempFiles = Get-ChildItem -Path $rootDirectory -Recurse -Directory -Force -Filter "Temp" -ErrorAction SilentlyContinue | ForEach-Object {
    $tempDirectory = $_.FullName
    Get-ChildItem -Path $tempDirectory -File -ErrorAction SilentlyContinue | ForEach-Object {
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        [PSCustomObject]@{
            FolderPath = $_.Directory.FullName
            FileName = $_.Name
            SHA256Hash = $hash
            ModifiedDate = $_.LastWriteTime
            FileSize = $_.Length
        }
    }
}

# Convert the $tempFiles to a formatted table string
$tableString = $tempFiles | Format-Table -AutoSize | Out-String -Width 5000

# Save the results to the main output text file
$tableString | Out-File -FilePath $tempFilesMetadataTableFilePath


# Save the full file details to the main output CSV file
$tempFiles | Export-Csv -Path $tempFilesMetadataFilePath -NoTypeInformation

# Extract just the SHA256 hashes as a plain list and save them to the hashes CSV file
$hashes = $tempFiles | Select-Object -ExpandProperty SHA256Hash
$hashes -join "`n" | Out-File -FilePath $tempFilesMetadataTableSignaturePath

Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Log-TaskCompletion -taskName "Temp Directory Collection"

############# Windows Directories #############

Write-Output "Windows Directories:"

# Define the directories for which to collect file metadata
$targetDirectories = @(
    "C:\Windows\System32",
    "C:\Windows",
    "C:\Windows\SysWOW64",
    "C:\Users\$env:UserName\AppData\Local",
    "C:\Users\$env:UserName\AppData\LocalLow",
    "C:\Users\$env:UserName\AppData\Roaming",
    "C:\Users\$env:UserName\AppData\Roaming\Microsoft",
    "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Windows",
    "C:\",
    "C:\Users\$env:UserName",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Users\$env:UserName\Documents",
    "C:\Users\$env:UserName\Downloads",
    "C:\Users\$env:UserName\Desktop",
    "C:\Users\Public",
    "C:\Users\$env:UserName\AppData\Local\Microsoft\Windows\INetCache",
    "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Windows\Printer Shortcuts",
    "C:\Windows\Fonts",
    "C:\Users\$env:UserName\Application Data", # For compatibility with older Windows versions
    "C:\ProgramData",
    "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
)

# Iterate through each target directory and collect file metadata
foreach ($directory in $targetDirectories) {
    # Create a folder for the target directory
    $targetFolderName = (Split-Path $directory -Leaf) -replace '[\\/:*?"<>|]', '_'
    $targetFolderPath = Join-Path $collectedFilesFolder $targetFolderName
    if (-Not (Test-Path -Path $targetFolderPath)) {
        New-Item -ItemType Directory -Force -Path $targetFolderPath | Out-Null
    }

    # Define the output file paths for the file metadata table and CSV
    $outputFilePathTxt = Join-Path $targetFolderPath "File_Metadata.txt"
    $outputFilePathCsv = Join-Path $targetFolderPath "File_Metadata.csv"

    # Initialize an array to store the file metadata
    $fileMetadata = @()

    $files = Get-ChildItem -Path $directory -File 

    foreach ($file in $files) {
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $fileData = [PSCustomObject]@{
            FolderPath = $file.DirectoryName
            FileName = $file.Name
            SHA256Hash = $hash
            ModifiedDate = $file.LastWriteTime
            FileSize = $file.Length
        }
        $fileMetadata += $fileData
    }

    # Convert the $fileMetadata to a formatted table string and save it to the .txt file
    $tableString = $fileMetadata | Format-Table -AutoSize | Out-String -Width 5000
    $tableString | Out-File -FilePath $outputFilePathTxt

    # Save the file metadata to the .csv file
    $fileMetadata | Export-Csv -Path $outputFilePathCsv -NoTypeInformation
     Write-Output "$directory"
}

Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Log-TaskCompletion -taskName "Windows Directories File Collection"

############# 05. Task Scheduler #############

Print-TaskStart -taskName "Scheduled Task Collection"
Get-ScheduledTask | Out-File -FilePath $scheduledTaskFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Log-TaskCompletion -taskName "Scheduled Task Collection"

############# 06. PREFETCH #############

# Gather contents of the Prefetch folder
Print-TaskStart -taskName "Prefetch Collection"
$prefetchFolderPath = "C:\Windows\Prefetch"
Copy-Item -Path $prefetchFolderPath -Destination $prefetchFilesFolder -Recurse -Force
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Log-TaskCompletion -taskName "Prefetch Files Collection"



############# 07. BROWSER #############

Print-TaskStart -taskName "Browser Collection"

####CHROME####
Write-Output "Chrome"
$chromeHistoryPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Google\Chrome\User Data\Default\History"
Copy-Item -Path $chromeHistoryPath -Destination $ChromebrowserHistoryRawFilePath -Force

# Read the browser history file
$historyFilePath = $ChromebrowserHistoryRawFilePath
$historyContent = Get-Content -Path $historyFilePath -Raw

# Define a regex pattern to match URLs
$urlPattern = '(?i)(?:https?://|www\.)[^\s/$.?#].[^\s]*'

# Find all URLs in the history content
$urls = [regex]::Matches($historyContent, $urlPattern) | ForEach-Object {
    $_.Value
}

# Filter out non-URL entries
$filteredUrls = $urls | Where-Object { $_ -match '^https?://' }

# Join filtered URLs using newline characters
$urlsFormatted = $filteredUrls -join "`r`n"

# Output the formatted URLs
$urlsFormatted | Out-File -FilePath $ChromebrowserHistoryParsedFilePath

Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

####EDGE####
Write-Output "Edge"
$edgeProfilesPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Edge\User Data"
$edgeHistoryFiles = Get-ChildItem -Path $edgeProfilesPath -Filter "History" -Recurse -File

$edgeUrls = @()
$rawOutput = ""

foreach ($historyFile in $edgeHistoryFiles) {
    $historyContent = Get-Content -Path $historyFile.FullName -Raw

    $urls = [regex]::Matches($historyContent, $urlPattern) | ForEach-Object {
        $_.Value
    }

    $filteredUrls = $urls | Where-Object { $_ -match '^https?://' }

    $edgeUrls += $filteredUrls
    $rawOutput += $historyContent + "`r`n"
}

$edgeUrlsFormatted = $edgeUrls -join "`r`n"

# Output Edge URLs
$edgeUrlsFormatted | Out-File -FilePath $EdgebrowserHistoryParsedFilePath
$rawOutput | Out-File -FilePath $EdgebrowserHistoryRawFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

####FireFox####
Write-Output "FireFox"
$firefoxProfilesDir = "$env:APPDATA\Mozilla\Firefox\Profiles"
$profileDirs = Get-ChildItem -Path $firefoxProfilesDir -Directory | Sort-Object -Property LastWriteTime -Descending

# Get the latest profile directory
$latestProfileDir = $profileDirs[0].FullName

# Construct the path to the history database file
$historyDbPath = Join-Path -Path $latestProfileDir -ChildPath "places.sqlite"

# Copy the SQLite database file to a text document
$copyDestination = $FireFoxbrowserHistoryRawFilePath
Copy-Item -Path $historyDbPath -Destination $copyDestination -Force

$inputFilePath = $FireFoxbrowserHistoryRawFilePath
$outputFilePath = $FireFoxbrowserHistoryParsedFilePath

# Read the contents of the input file
$fileContent = Get-Content -Path $inputFilePath -Raw

# Define your regular expression pattern
$regexPattern = '(?i)(?:https?://|www\.)[^\s/$.?#]+\.[^\s]*'

# Use the regex pattern to match and extract desired information
$matches = [regex]::Matches($fileContent, $regexPattern)

# Create a formatted output string
$formattedOutput = foreach ($match in $matches) {
    # Process each match and generate the formatted output
    $formattedLine = $match.Value
    $formattedLine
}

# Write the formatted output to the output file
$formattedOutput | Out-File -FilePath $outputFilePath
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Log-TaskCompletion -taskName "Browser Collection"

############# 08. Anti Virus #############

Print-TaskStart -taskName "Anti Virus"


### AV products Info ###
Write-Output "AV Products Info"

Function ConvertTo-NPHex {
    Param([int]$Number)
    "0x{0:x}" -f $Number
}

# Define the query to retrieve antivirus product information
$query = "SELECT * FROM AntiVirusProduct"

# Get the antivirus product information using WMI
$antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $query

$Products = @()

# Process each antivirus product to determine status
foreach ($product in $antivirusProducts) {
    $hex = ConvertTo-NPHex $product.productState
    $mid = $hex.Substring(3, 2)
    $end = $hex.Substring(5)

    $Enabled = $mid -notmatch "00|01"
    $UpToDate = $end -eq "00"

    $Products += [PSCustomObject]@{
        Name = $product.displayName
        ProductState = $product.productState
        Version = $product.productVersion
        PathToSignedProductExe = $product.pathToSignedProductExe
        PathToSignedReportingExe = $product.pathToSignedReportingExe
        Enabled = $Enabled
        UpToDate = $UpToDate
        Updated = (Get-Date -Date $product.Timestamp).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

# Output to Text File
$filePathTxt = $antivirusLogFilePath
$Products | ForEach-Object {
    "Name: $($_.Name)" | Out-File -FilePath $filePathTxt -Append
    "Version: $($_.Version)" | Out-File -FilePath $filePathTxt -Append
    "Path to Signed Product Exe: $($_.PathToSignedProductExe)" | Out-File -FilePath $filePathTxt -Append
    "Path to Signed Reporting Exe: $($_.PathToSignedReportingExe)" | Out-File -FilePath $filePathTxt -Append
    "Enabled: $($_.Enabled)" | Out-File -FilePath $filePathTxt -Append
    "UpToDate: $($_.UpToDate)" | Out-File -FilePath $filePathTxt -Append
    "Updated: $($_.Updated)" | Out-File -FilePath $filePathTxt -Append
    "------------------------------------------------" | Out-File -FilePath $filePathTxt -Append
}

# Output to CSV File
$filePathCsv = $antivirusCSVLogFilePath
$Products | Export-Csv -Path $filePathCsv -NoTypeInformation

Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

### DEFNEDER QUARANTINE FOLDER ###
Write-Output "Defender Quarantine"

# Define the path to the Windows Defender quarantine folder
$quarantineFolderPath = "C:\ProgramData\Microsoft\Windows Defender\Quarantine"


# Define the output file paths for the file metadata table and CSV
$outputFilePathTxt = Join-Path $quarantineFolder "Quarantine_File_Metadata.txt"
$outputFilePathCsv = Join-Path $quarantineFolder "Quarantine_File_Metadata.csv"

# Initialize an array to store the file metadata
$fileMetadata = @()

 # Use 2>$null to suppress the non-terminating errors from Get-ChildItem
 $files = Get-ChildItem -Path $quarantineFolderPath -File 2>$null

# Collect file metadata for the files in the quarantine folder
foreach ($file in $files) {
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if ($hash -ne $null) {
        $fileData = [PSCustomObject]@{
            FolderPath = $file.DirectoryName
            FileName = $file.Name
            SHA256Hash = $hash
            ModifiedDate = $file.LastWriteTime
            FileSize = $file.Length
        }
        $fileMetadata += $fileData
    }
}

# Convert the $fileMetadata to a formatted table string and save it to the .txt file
$tableString = $fileMetadata | Format-Table -AutoSize | Out-String -Width 5000
$tableString | Out-File -FilePath $outputFilePathTxt

# Save the file metadata to the .csv file
$fileMetadata | Export-Csv -Path $outputFilePathCsv -NoTypeInformation
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
Log-TaskCompletion -taskName "Anti Virus Collection"


############# 09. EVENT LOGS #############
Print-TaskStart -taskName "Event Logs Collection"

# Function to gather and save event logs
function GetAndSaveEventLogs {
    param (
        [string]$logName,
        [string]$logFileName
    )
    
    Write-Output $logName
    $eventLog = Get-WinEvent -LogName $logFileName
    
    $logFilePath = Join-Path $eventLogsFolder "$logName.txt"
    $eventLog | Out-File -FilePath $logFilePath
    
    # Copy the .evtx file to the destination folder
    $evtxPath = if ($logName -eq "Windows PowerShell (Operational)") {
        "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    } elseif ($logName -eq "Windows Defender (Operational)") {
        "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx"
    } elseif ($logName -eq "Windows Defender (WHC)") {
        "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4WHC.evtx"
    } else {
        "C:\Windows\System32\winevt\Logs\$logName.evtx"
    }

    $destinationEvtxPath = Join-Path $eventLogsFolder "$logName.evtx"
    Copy-Item -LiteralPath $evtxPath -Destination $destinationEvtxPath -Force
}

# Get and save the event logs
GetAndSaveEventLogs -logName "System" -logFileName "System"
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
GetAndSaveEventLogs -logName "Security" -logFileName "Security"
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
GetAndSaveEventLogs -logName "Application" -logFileName "Application"
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
GetAndSaveEventLogs -logName "Windows PowerShell" -logFileName "Windows PowerShell"
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
GetAndSaveEventLogs -logName "Windows PowerShell (Operational)" -logFileName "Microsoft-Windows-PowerShell/Operational"
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
GetAndSaveEventLogs -logName "Windows Defender (Operational)" -logFileName "Microsoft-Windows-Windows Defender/Operational"
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts
GetAndSaveEventLogs -logName "Windows Defender (WHC)" -logFileName "Microsoft-Windows-Windows Defender/WHC"
Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

Log-TaskCompletion -taskName "Event Logs Collection"

################Compress Files & Clean Up################

# Start a background job to compress all the files in the investigation folder into a zip file
$compressionJob = Start-Job -ScriptBlock {
    param ($srcPath, $destPath)
    Compress-Archive -Path $srcPath -DestinationPath $destPath
} -ArgumentList $investigationFolderPath, $zipFilePath

# Wait for the compression job to complete
Wait-Job $compressionJob | Out-Null

#Remove Investigation Root dir leaving only new Zip
Remove-Item -Path $investigationFolderPath -Recurse

Update-ProgressBar -current (++$progressCounter) -total $totalArtifacts

################Completion################

## Add a completed  progress update to ensure the progress bar is created
Write-Progress -Activity "Gathering Artifacts" -Status "Complete" -PercentComplete 100
Write-Host ""
Write-Host "Package Collection Complete!" -ForegroundColor Green
Write-Host "Package Filepath: $zipFilePath"
Write-Host ""
Write-Host "=========================================================================="
Write-Host ""
Write-Host $footerText
Write-Host ""
Write-Host "=========================================================================="
$ErrorActionPreference = "Continue"

