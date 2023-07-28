![Logo1](https://github.com/GOadn4p/PwrPackage/assets/139599365/3b3fa824-19ac-4041-8246-afc9dc7f7f0c)


## Tool Description

This is an open source free to use tool for collecting a forensic package from a host. The tool is built in PowerShell and leverages 
 windows built in methods to retrieve the data required.

The tool retrieves the following information categories:
- Process data
- Network data
- Registry data
- Scheduled Tasks
- File Collection
- Browser data
- Prefetch 
- Event Logs
- AntiVirus data


## Purpose

This tools purpose is to open up forensic options to smaller organisations, SOC teams or independent users. This tool collects investigatory packages from the host using well known methods within incident response and gives a solid coverage of host events. The end goal is to make the output of this tool usable in analysis work when understanding a compromise or incident. However this tool cannot guarantee that events of a threat have been detected only what is within the tools capabilities.

This tool is not a complicated and only draws on already known incident response methods, the goal is merely automating this in a free, open source format. Not everyone can afford the shiny cyber tool kits...


## Installation/How to use (PowerShell CLI)

1. Open file explorer navigate to Desktop.
2. Select file > PowerShell > Run PowerShell as Administrator.
3. Run the following command to get PwrPackage:
```
$url = 'https://raw.githubusercontent.com/GOadn4p/PwrPackage/main/PwrPackage.ps1'; $HowToUseURL = 'https://raw.githubusercontent.com/GOadn4p/PwrPackage/main/HowToUse.txt'; $dest = Join-Path ([Environment]::GetFolderPath("Desktop")) 'PwrPackage'; if (-Not (Test-Path $dest -PathType Container)) { New-Item -ItemType Directory -Path $dest | Out-Null }; (New-Object net.webclient).DownloadFile($url, (Join-Path $dest 'PwrPackage.ps1')); (New-Object net.webclient).DownloadFile($HowToUseURL, (Join-Path $dest 'HowToUse.txt'))
```
3. Invoke/Execute PwrPackage using following command:
```
Set-ExecutionPolicy Bypass -Scope Process -Force; cd "$([Environment]::GetFolderPath('Desktop'))\PwrPackage"; .\PwrPackage.ps1
```
4. Nice! Your package location will be printed to terminal at the end.


## Installation/How to use (Zip Download CLI)

1. Download the files as a .zip.
1. Extract Files from the Zip.
1. Navigate to Extracted folder in file explorer.
2. Select file > Powershell > Run PowerShell as Administrator
2. Copy the following command:
`powershell.exe -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; powershell.exe -NoExit -File 'PwrPackage.ps1'"`
2. Paste this into you PowerShell window and hit enter.
2. Voila! _(Please be patiant and observe the progress bar and output statements. The script may run slowly if there are a lot of artifacts to gather.)_
1. When the script is finished your final Investigation Package will be located at `C:\Users\<USER>\Desktop\InvestigationPackage.zip`


## Authenticity and Integrity

### PwrPackage.ps1

#### Checksums
- **SHA256 Hash:** CD153C837DD2E2008FAD7B75E6B04C1FDC6D7DC15702D526F7C7128D4C772D47
- **MD5 Hash:** 1AE108E7A7BBC02A0955761CEA4324F2
- **VT Link:** 


### HowToUse.txt

#### Checksums
- **SHA256 Hash:** 67EA2DBA863C145880D9BE120FBD0357DD0DBF2DDAF02650F76CC9A0F75D2E78
- **MD5 Hash:** 2CA0C54FD5017FBAD125A3DE310C1500
- **VT Link:** 


## Acknowledgements 

- ChatGPT - Honestly I'm not great at coding so I asked AI to help me bring this idea to fruition.
- @xorjosh - Thank you for your useful feedback.
