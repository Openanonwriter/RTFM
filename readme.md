```
RRRRRRRRRRRRRRRRR   TTTTTTTTTTTTTTTTTTTTTTTFFFFFFFFFFFFFFFFFFFFFFMMMMMMMM               MMMMMMMM
R::::::::::::::::R  T:::::::::::::::::::::TF::::::::::::::::::::FM:::::::M             M:::::::M
R::::::RRRRRR:::::R T:::::::::::::::::::::TF::::::::::::::::::::FM::::::::M           M::::::::M
RR:::::R     R:::::RT:::::TT:::::::TT:::::TFF::::::FFFFFFFFF::::FM:::::::::M         M:::::::::M
  R::::R     R:::::RTTTTTT  T:::::T  TTTTTT  F:::::F       FFFFFFM::::::::::M       M::::::::::M
  R::::R     R:::::R        T:::::T          F:::::F             M:::::::::::M     M:::::::::::M
  R::::RRRRRR:::::R         T:::::T          F::::::FFFFFFFFFF   M:::::::M::::M   M::::M:::::::M
  R:::::::::::::RR          T:::::T          F:::::::::::::::F   M::::::M M::::M M::::M M::::::M
  R::::RRRRRR:::::R         T:::::T          F:::::::::::::::F   M::::::M  M::::M::::M  M::::::M
  R::::R     R:::::R        T:::::T          F::::::FFFFFFFFFF   M::::::M   M:::::::M   M::::::M
  R::::R     R:::::R        T:::::T          F:::::F             M::::::M    M:::::M    M::::::M
  R::::R     R:::::R        T:::::T          F:::::F             M::::::M     MMMMM     M::::::M
RR:::::R     R:::::R      TT:::::::TT      FF:::::::FF           M::::::M               M::::::M
R::::::R     R:::::R      T:::::::::T      F::::::::FF           M::::::M               M::::::M
R::::::R     R:::::R      T:::::::::T      F::::::::FF           M::::::M               M::::::M
RRRRRRRR     RRRRRRR      TTTTTTTTTTT      FFFFFFFFFFF           MMMMMMMM               #WIDICK#
```
# RTFM "Read the Field Manual"  
Customization Possible: This is a powershell script, audit, rebuild, repeat. 

RTFM is a modular PowerShell script designed for rapid computer diagnostics and information gathering. It encapsulates and relies upon a curated selection of third-party tools within a menu-driven interface.  I'm using AI capabilities to accelerate RTFM's development with rapid error checking and I invite collaboration.

Why Powershell: PowerShell offered a convenient and versatile solution with a great support built in to windows. It's already included in Windows 10 and 11, removing the hassle of installing additional software while guaranteeing compatibility.


> **Warning**
> !!!  This .EXE is highly likely to be detected by antivirus software.  If you don't understand the risks or the source code behind this executable, DO NOT run it. 
Please read for more information https://github.com/MScholtes/PS2EXE/issues/111 !!! <br>
> !!! This PowerShell script modifies files. It's your responsibility to verify all settings and paths before running. Proceed at your own risk.
!!!<br>
>  I take no liability for any potential damages. <br>
 


## PRE-MENU
Provides essential system information:  This includes your Windows version (Windows 11 Pro 23H2), how long the system has been running (uptime), when it was last booted, and the original installation date. <br>

Indicates Windows activation status:  This tells you whether your copy of Windows is currently considered "Licensed," in a "Grace" period, or "Unlicensed." This has implications for features and updates you might receive.<br>

Reveals the general Windows license type:  This information (e.g., OEM, Retail, Volume) hints at how the operating system was originally purchased and can affect your upgrade options.<br>

Checks BitLocker encryption status: It lets you know if BitLocker, a drive encryption feature, is currently protecting your main system drive (C:).

Important Notes:<br>
If you see a BitLocker recovery key listed, make sure to store it very securely. This key is the only way to recover data if you ever lose access to your encrypted drive.<br>


## (HARDWARE) INFO 


## NDT (NETWORK DIAGNOSTIC TOOL)
### (EIP) External IPv4
EIP checks your external IP using Invoke-RestMoethod to https://ipinfo.io/ or https://checkip.amazonaws.com/ if first request fails.

### Network (Info)
#### Wired Network Details: 
Identifies the network adapter, IP address, subnet mask, default gateway, and DNS servers. <br>
<br>

#### Wireless Status:
Reports whether the wireless network service is running. If not running, attempts to generate a report detailing wireless events, network profiles, and certificates.<br>
<br>

#### Remote Access 
Configuration: Checks the status of standard remote access tools (WinRM, OpenSSH Server, Windows Remote Desktop)<br>
<br>

#### Remote Software: 
Tries detecting the presence Third-Party installed remote access programs like AnyDesk.<br><br>
VPN Indicators: Scans for traces of VPN configurations and programs.<br>
BOTH Remote Software and VPN just use recursive funtions to check names in the registry, running processes and temp files, can be wildly inacurate, but handy for quick checks. <br>

### iperf3
This is the command line version of iperf3, with a quick custom menu making it easy to set up iperf3 in seconds for a custom TCP protnumber. 

### Nmap 
Comand line version of nmap. With depenency checking if npcap.exe is installed. 

### TNC
A random placebolder of giberish until i add in other diagnostic tools, why dont i remove it, because im to busy adding and fixing other things. 

## (Hardware) Info
#### Motherboard: 
Displays manufacturer, product name, serial number, and version.
#### RAM:
Provides RAM type (DDR, DDR2, DDR3, DDR4, etc.).
Lists the total number of populated memory slots and total DIMM slots available.
Reports the total amount of RAM installed in GB.
Displays detailed information about each individual RAM stick, including:
Bank Label, Manufacturer, Part Number, Speed, Memory Type
#### CPU:
Displays the processor's name, socket designation, number of physical sockets, total cores, and the number of logical processors (threads).
Reports the maximum clock speed in MHz.

#### Storage Health (CrystalDiskInfo Integration)

Runs CrystalDiskInfo: Executes the CrystalDiskInfo utility to retrieve S.M.A.R.T. (Self-Monitoring, Analysis, and Reporting Technology) data from your storage drives.
Analyzes S.M.A.R.T Data:
Parses the CrystalDiskInfo output file, extracting health status, percentages, and relevant S.M.A.R.T attributes for each drive.
Beeps and displays a warning in red if a drive's health status is not "Good" or its SSD health percentage falls below 80%.
Provides detailed S.M.A.R.T attribute readings, including raw values and their associated attribute names.

#### Overall Purpose

This script gathers essential hardware information about your computer, with a focus on motherboard, RAM, CPU, and storage health monitoring. It  leverages CrystalDiskInfo to provide insights into potential drive issues.

Important Notes:

CrystalDiskInfo Required: You'll need a copy of CrystalDiskInfo (DiskInfo64.exe) placed in the same directory or lower than this script for the storage analysis functionality to work.
Filtering: The script has extensive filtering to tailor the CrystalDiskInfo output, reducing unnecessary information.

## (APP)
Checks Registry Uninstall keys listed below, and Program files for anti-virus. In later versions this will be moved. 
## (Windows) 
#### Disk Partition Type

Determines Windows Partition Style: Identifies whether the partition scheme on the disk containing your Windows installation is MBR (Master Boot Record) or GPT (GUID Partition Table). This information is crucial for understanding system compatibility and certain upgrade/recovery operations.
#### Disk Capacity Monitoring

Reports Disk Usage: Checks the usage percentage of each logical disk on your system.
Alerts for Near-Full Disks: If a disk exceeds a set usage threshold (default 90%), the script emits a beep and displays the disk information in red, highlighting potential storage bottlenecks.
#### Anti-Virus Status

Lists Active Anti-Virus Products: Queries your system to display the name and status (definition updates, real-time protection) of installed anti-virus software.
#### Windows Updates

Checks for Available Updates: Searches for uninstalled Windows updates and categorizes them into Critical, Important, and Optional. Displays the counts for each category.
Requires Internet: It needs internet access to check for updates from Microsoft servers.
#### Diagnostic Data

SFC Scan Status: Attempts to provide the date of the last system file check (SFC) run, which is a tool for repairing corrupt system files. If not found, it mentions when the diagnostic log began.

Mini-Dumps: Checks for the presence of mini-dumps (crash logs) in the standard Windows directory. A high number of mini-dumps may suggest system instability.
Symbol Path Configuration: Ensures the _NT_SYMBOL_PATH environment variable is set correctly. This is needed for advanced debugging and symbol resolution during crash analysis.

Mini-Dump Analysis (Optional): If the script locates mini-dumps and a tool called dumpchk.exe is available, it offers a basic menu to analyze individual crash files. This provides BugCheck codes and parameters that could be useful for troubleshooting.
Overall Purpose: This script provides a quick snapshot of system health, focusing on disk usage, basic diagnostics, installed anti-virus software, and the presence of pending Windows updates.

Important Notes:

Limited Error Handling: The script includes some basic error handling but might not gracefully handle all potential issues.

## (6)Install Anydesk, Malwarebytes, AdobeReader, Chrome

Does exactly as name implies but uses Winget to download, verify, and install. May not work if you have not accepted terms and conditions of winget.

## (Repair) Windows

Runs SFC, checks to see if SFC failed, and if so runs SFC and DISM again. 



Registries Checked
```
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
```
|3rd Party Remote|3rd Party VPN| Anti-Virus|
|---|---|---|
|AeroAdmin |	ExpressVPN| Avast |
|Ammyy Admin |	NordVPN| AVG |
|AnyDesk |	CyberGhost| Avira|
|Anyplace Control |	IPVanish| Bitdefender| 
|Apple Remote Desktop |	Private Internet Access| ZoneAlarm |
|Bomgar |	Hotspot Shield| Immunet | ClamWin|
|Chrome Remote Desktop |	Windscribe| Comodo |
|Cisco WebEx |	TunnelBear| Dr.Web |
|Citrix GoToAssist |	VyprVPN| ESET| 
|ConnectWise Control |	Surfshark| F-Secure| 
|Dameware Remote Everywhere |	ProtonVPN| G DATA|
|DeskRoll |	HideMyAss| Kaspersky| 
|DWService |	TorGuard| Malwarebytes |
|FreeRDP |	Astrill| McAfee|
|GoToMyPC |	Mullvad| Windows Defender|
|ISL Light |	IVPN| NANO |
|ISL Online |	PrivateVPN| Norton |
|Join.me |	PureVPN| Panda| 
|LiteManager |	SaferVPN| 360 Total Security|
|LogMeIn |	ZenMate| Sophos |
|Mikogo |	StrongVPN| Titanium |
|Microsoft Intune |	AirVPN| TrustPort|
|Microsoft Remote Desktop |	CactusVPN| Vba32|
|mRemoteNG |	FastestVPN| Viper| 
|NetSupport Manager |	FrootVPN|Sentinel|
|NoMachine |	GooseVPN| Webroot |
|Parallels Access |	Hide.me| |
|Radmin |	iPredator||
|RDPSoft    |	IronSocket||
|RDP Wrapper Library |	KeepSolid VPN Unlimited||
|RealVNC |	LiquidVPN||
|Remote Desktop Commander |	Norton Secure VPN||
|Remote Desktop Connection Manager |	Perfect Privacy||
|Remote Desktop Manager	|VPN.ht||
|Remote Desktop Organizer |	VPNArea||
|Remote Desktop Plus |	VPNBook||
|Remote Desktop Spy |	WireGuard||
|RemoteToPC	FortiClient | VPN||
|Remote Utilities	|||
|Remmina	|||
|ScreenConnect |||
|ShowMyPC |||
|SimpleHelp |||
|SolarWinds MSP Anywhere |||
|Splashtop |||
|Supremo |||
|SysAid	|||
|TeamViewer |||
|Terminals	|||
|Thinfinity Remote Desktop|||
|TightVNC	|||
|UltraVNC	|||
|VNC Connect|||
|WebEx	|||
|Zoho Assist|||

# How to build

Grab your self a flash drive 32GB flashdrive or larger as every tech does, but only 1gb needed atm for RTFM. 

1. Download and extract archive from https://git.artificialfreedom.com/tony/RTFM/archive/main.zip

2. Move the downlaoder.ps1 scrilpt to your flashdrive, Run the downloader.ps1 script and let it do its job or if your a business create a folder at the Called Tools and move to step 3.  
(Home users only, do not use if your a business! Licnesing for most of these programs are for home users only) Please adhere to licnesing.  

3. Go forth and find the programs to download. Download and exact these programs in to anyfolder, below RTFM. <kb>
This is my current setup. 
```
.
├── RTFM.exe
├── RTFM.ps1
├── Tools
│   ├── Hardware
│   │   ├── CrystalDiskInfo9_2_3
│   │   └── cpu-z
│   ├── Networking
│   │   ├── iperf3
│   │   └── nmap-7.92
│   ├── SysinternalsSuite
│   └── Windows
│       └── DBG
└── readme.md
```

4. Download WinDbg: <br>
Visit the Windows SDK download page.
Download the Windows SDK. https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/<br>
During installation, select only the Debugging Tools for Windows component.<br>
Copy WinDbg Executable:<br>
Once installed, navigate to the installation directory. Typically, it’s located at C:\Program Files (x86)\Windows Kits\10\Debuggers\x64.<br>
Create a Portable Version by copying that directy into a desired location, such as ./Tools/Windows/DBG/.<br>
Now you have a portable version of WinDbg that can be used to analyze BSOD (Blue Screen of Death) codes.<br>

5. Run RTFM.exe 
