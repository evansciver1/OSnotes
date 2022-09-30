-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Day 1
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Powershell:
  - CIM classes are general collections of objects which fall under specific criteria; pull things directly from the kernel
  - CIM classes are a form of persistence; Win32 is exclusively microsoft
  - 'get-wmiobject win32_process | select -first 2 -erroraction silentlycontinue' syntax to take first 2 fields from the output of a get win32 command and ignore error messages
  - Remote sign allows you to run any script as long as it isnt on the local machine
  - get-executionpolicy shows execution policy; powershell reads policy before opening profiles
  - $profile.allusersallhosts applies to everyone; persistence using this looks for highest precdent
  - '($profile | get-member -membertype noteproperty).name | foreach-object { if ((test-path $PROFILE.$_) -eq $true) { write-host "$PROFILE.$_" -foregroundcolor green -nonewline ; write-host "exists" }}'
    getss user profiles and confirms they exist
  - Remoting:
    - requires windows remote management to be running [winrm]
    - 'get-item wsman:\localhost\client\trustedhosts' shows what computers are trusted to remote in; by default only allows one addition
    - using quotes around what you want to add w/get-item allows multiple additions i.e. ... -value "10.20.30.40,not_kremlin.ru" will add both
    - 'invoke-command' also works to temporarily remote in i.e. 'Invoke-Command -ComputerName File-Server {Get-Service}'
    - using -asjob while querying a large number of hosts or data requires the recieve-job command to be run after 
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Day 2
-------------------------------------------------------------------------------------------------------------------------------------------------------------------    
 Registry Structure:
  - 'Reg.exe, Regedit (registry editor)' tools to edit the registry
  - 'HKLM\software\microsoft\windows\CurrentVersion\run' - anything in this key is run whenever the system is started/restarted
  - Hive keys/HKs - HKLM/HKEY_USERS/HKEY_CURRENT_USERS/HKEY_CURRENT_CONFIG/HKEY_CLASSES_ROOT
  - Reg.exe will treat everthing as the absolute path; using tab, *, etc. doesn't work because reg believes that's the actual path
  - get-item will query individual keys; get-childitem will get all keys under a certain path i.e. all keys under HKLM\Software
  - get-itemproperty gives values and properties of individual registry entry
  - Add the registry location 'HKey_Users' as a PS drive: 'new-psdrive -name hku -psprovider registry -root HKEY_USERS'
  - Query a registry location without calling a PSDrive: 'get-item registry::hkey_local_machine\system\currentcontrolset\services\backdoorsvc'
  - Query a registry location subkeys: 'get-childitem hklm:\system\currentcontrolset\services\backdoorsvc'
  - Query a registry value (entry): 'get-itemproperty -path hklm:\system\currentcontrolset\services\backdoorsvc -name "beacon"'
  - Powershell getting user SIDS: 'get-localuser | select name,sid'
 Alternate Data Streams:
  - Only exist in NTFS drive; cannot be disabled
  - '[filename.extension]:[alternate_stream_name]:$DATA' every file looks at the $DATA stream
  - Command prompt is the easiest way to create and view data streams
  - powershell - 'get-childitem | foreach-object { get-item $_.FullName -stream * | where { $_.stream -ne ':$DATA'} }' shows alternate data streams in powershell
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Day 3
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Linux Essentials:
    File System:
      - Everything falls under Root - /etc /bin /sbin /sys /dev /boot etc.
      - /bin: configurable binaries
      - /etc: everything thats configurable 
      - /sys: system files
      - /sbin: system binaries
      - /var: variable data files - system logs, etc.
      - /home: users home folders
      - /proc: pseudo file system designed to hold info related to processes running on the system as long as the system is running
      - /dev: IO devices - CAC reader, mouse, keyboard, monitor, etc.
      - /usr: universal system resources - where files meant to be used across the entire system are held i.e. man pages
      - /boot: anything that runs on startup - grub config, grub, etc.
      - /lib & /lib64: static object files; similar to .dll files in windows
      - /mnt: permenantly mounted file systems - network drives, usb harddrive, etc.
      - /media: removable media - CDs, USBs, etc.
      - /tmp: temporary files - everyone can write to /tmp
      - /run: information about the system pertaining to the particular session of the computer running
      - /root: home directory for root
      - /opt: placeholder for user installed software
      - /srv: files for services the system is running
    Commands:
      - 'which' finds the location of commands
      - 'whereis' like which but better
      - 'id' user, what group the user is in
      - 'whoami' who the user youre acting as is
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Day 4
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Windows Boot Process:
    - BCDEDIT
    -
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Day 5
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Linux Boot Process:
    - Big Mike Got Killed In Russia - BIOS, MBR, GRUB, Kernel, Init, RunLevels
    - 'lsblk' - shows devices currently being used
    - 'sudo xxd -l 512 -g 1 /dev/sda' - checks the contents of the MBR
    - 'sudo dd if=[MBR location - SDA or VDA) of=(New Copy of MBR) bs=1 count=512'
    - 'cat /boot/grub/grub.cfg'
    - 'ls -l /sbin/init' determines which init system youre using
    - 'cat /etc/environment' shows environmental variables - usually shows the path statement
    - /etc/profile sets environment whenever someone logs in41
    BIOS:
      - Performs POST
      - First program to run on startup
      - Performs system integrity checks
      - Builds a device tree
    MBR:
      - Located at the very beginning of the bootable dist (512 bytes) and contains the primary bootloader, partition table, and MBR validity check
      - Contains code for GRUB
      - Typically located at /dev/hda, /dev/sda, or /dev/vda
      - 'du' - disk usage
      - 'df' - disk free
    GRUB:
      - Dynamically configurable with the capability to make changes during boot
      - Config file - '/boot/grub/menu.lst' or '/boot/grub/grub.cfg'
      - Altering boot entries, selecting different kernels, and modifying the initial RAM disk
      - 'linux /boot/vmlinuz-4.15.0-76-generic root=LABEL=cloudmg-rootfs ro console=tty1 console=ttyS0' command that loads the kernel
      - 'service <service name> start | stop | restart | status | reload | ...' script that runs services
      - 'service --status-all'
    Kernel:
      - Uncompresses itself into RAM
      - Establishes memory management and detects CPU type
      - mounts the root '/' filesystem
      - Kernel is process 0 [kthreadd]
      - Executes /sbin/init or systemd daemon
    Init:
      - Configures environment for the system
      - Looks at the /etc/inittab
        SystemV:
          - Available run levels 0 - 6
          - Identifies the default init run level from /etc/inittab and uses that to load all the appropriate programs
          - '/etc/inittab' showss different run levels
          - '/etc/init.d' where scripts are stored
          - 'ls -l /etc/rc<1-6>.d'
        SystemD:
          - Loads system in parallel and from binaries
          - 'default.target' is the default runlevel
          - use 'systemctl' to get default
          - 'ls -lisa /lib/systemd/system/default.target' symbolic link to default target
          - '/etc/systemd/system' possible file location for systemd files
          - '/lib/systemd/system' possible file location for systemd files
          - 'systemctl list-dependencies graphical.target' lists running dependent services by the default thing
          - 'systemtcl cat graphical.target' shows info for default target
    RunLevels:
      
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Day 6
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Windows Process Validity:
    - PIDS: 0-3 kernel, 4 system, 5-1000 system processes
    - Discovering normal, abnormal, and hidden processes and services:
      - 'Get-Process SMSS,CSRSS,LSASS | Sort -Property Id' checks processes running in those categories and their PIDs
      - 'Get-Process | Select Name, Id, Description | Sort -Property Id' syntax to show processes based on their PIDs showing descriptions
      - 'get-ciminstnace win32_process | ft -wrap | more' shows system processes and handle counts
      - 'get-wmiobject win32_process | where {$_.name -like "*[process name]*"} | select name, parentprocessid. processid, commandline | format-list' 
        gets processes and listed information and puts it in a list; can be used to find parent processes
      - Seeing a System instance with a pipe (i.e. System | petnya) is bad!
      - 'get-ciminstnace win32_process | select name parentprocessid, processid, commandline' shows ciminstance filtered on the parent process, 
        PID and command line (shows last command run) members
      - 'Get-Process | Select Name, Priorityclass' shows processes by level of priority
      - 'sc.exe showsid [service]' shows SIDs for services using sc
      - 'get-service | select displayname,servicename' shows display and service names
      - 'get-wmiobject win32_service | select name, displayname, processid | fl' shows all services and the process ID theyre running under
      - 'Tasklist /m' shows hidden processes
      - 'schtasks /query /tn ["\task name"] /v /fo list' shows detailed info about scheduled tasks
      - 'get-scheduledtask -taskpath \ ' shows tasks running from root director 
      - 'Get-ScheduledTask | Select * | Select -First 5' gets the first 5 scheduled tasks and shows specific information including 
         creation date and who created them
      - 'sc.exe query state-all' [powershell] queries scheduled processes
      - 'get-wmiobject win32_process | where {$_.processid -like "*[PID youre looking for]*"} | select name, parentprocessid. processid, commandline | 
        format-list' searches for a specific PID; useful for reverse searching parent processes after finding an unusual running process
      - Task Scheduler will show scheduled tasks in a GUI format; stay at the root level!
  Sysinternals:
    - Downloading Sysinternals: 
      - Open Powershell
      - 'net use * http://live.sysinternals.com' -or- 'new-psdrive -name "sysint" -psprovider filesystem -root "\\live.sysinternals.com\tools'
    - Procmon.exe: 
      - enable boot loggin by going to options and clicking generate thread profiling events
    - Autoruns64.exe:
      - shows everything that runs on startup
      - shows scheduled tasks - clicking on a suspicious task will show its path and what its doing
    - Procexp64.exe:
      - gives a hierarchical view of your processes - like task manager on crack
    - TCPView64.exe:
      - shows local ports and connections on them
    - PsExec64.exe:
      - allows you to run PS commands or scripts from one machine to another without actually using Pwsh; encrypts the session
    - Handle64.exe:
      - shows handle information
  UAC:
    - Registry key is located at: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    - UAC is all GUI based
    - Checking if Auto Elevate is True: '/strings C:\Windows\System32\*.exe -accepteula | select-string -SimpleMatch "autoelevate"'
    - Checking if Digitally Signed: './sigcheck -m C:\Windows\System32\slui.exe -accepteula | Select-String -SimpleMatch "level"'
    - Trusted Directory: 'C:\Windows\System32'
    - Checking Manifest: use either strings, sigcheck, or a really long command in pwsh.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Day 7
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Linux Processes:
    - Startup Processes:
      - For kernel-space processes: '[kthread] ( PID = 2 )' no non-kernel processes should have a parent PID of 2
      - For user-space processes: '/sbin/init ( PID = 1 )'
      - All kernel processes are forked from [kthread]; all user processes are forked from /sbin/init
      - 'ps -elf' shows running processes
      - 'ps -lf --ppid [1/2 depending on what processes youre looking for] --forest' slims down processes list to filter by parent ID 
        and shows a comprehensive geneology of procceses. Use grep to find a specific process by PID and add '--context [number]' to determine how many
        lines before/after are shown. '-B' only shows number of lines before, '-A' shows number of lines after
      - 'Top' shows a changing list of processes that are starting and stopping. 'Htop' shows a similar list with more detail. Going to options (f2) will
        allow you to add columns for more detail. The 'S' column changes from 'S' to 'Z' to show zombie processes. 
        'Btop' needs to be installed, and shows a very detailed list of processes and a bunch of other shit
    - Process Ownership - EUID, RUID:
      - EUID defines access rights for a process. RUID indicates who initiated a process
    - System Calls:
      - A system call is an interaction between a process and the kernel
      - 'Fork()' is when the kernel creates a nearly identical copy of the process
      - 'Exec()' is when the kernel starts a program, replacing the current process
    - Orphan and Zombie (Defunct) Processes:
      - Orphan processes are proceses whose parent has exited; adopted by sbin/init with PPID of 1
      - All daemons are orphans
      - 'Disown -a && exit' close a shell/terminal and force all children to be adopted
      - Zombie processes are completed processes but still have an entry in the process table, waiting on parent to acknowledge or terminate
      - Zombie cant be terminated with kill since it has already finished execution, unless the parent process that spawned it is killed
      - Fork bombs are denial of service attacks wherein a process creates processes that spawn more processes until the computer bluescreens
    - Daemons (services):
      - Daemons are programs that run as a background process. Purpose is to manage/monitor a service: {status, start, restart}
      - Daemons are services that should run for duration of system operation - since init is parent, it would require a shutdown for parent to die
      - 'ps -ppid 1 -lf' will show malicious processes orphaned and named to look like daemons
    - Job Control:
      - 'jobs' displays a list of jobs running in the background. 'fg' or 'bg' sends jobs to the foreground or background
      - 'kill %<job number>' terminates the process by job number
      - 'ctrl -z' or 'kill -19' stops or suspends the job. 'Kill -l' shows all signal interrupts
      - 'kill -9 <PID>' or 'pkill -9 <process name>' 
    - Cron Jobs:
      - Cron daemon checks the directories '/var/spool/cron' '/etc/cron.d' and '/etc/crontab' once a minute and executes any commands specified that match 
        on the line
        - Two types of cron jobs - system and user:
          - System cron jobs run as root and are rigidly scheduled; perform system-wide tasks, and are controlled by '/etc/crontab' and '/etc/cron.d'
          - User cron jobs are stored in '/var/spool/cron/crontabs/'
          - Use 'crontab' to create user cron jobs
          - 'crontab -u [user] file' sets users crontab file to the contents of the listed file
          - 'crontab -l -u [user]' displays users crontab contents
          - 'crontab -r -u [user]' removes users crontab contents
          - 'crontab -e -u [user]' edits users crontab contents
          - cron syntax: min - hour - day of month - month of year - day of week
    - 'sudo lsof' lists open files filtering by a particular process, showing a breakdown of every open file by every process on the system
    - 'sudo lsfo -p [PID]' shows all file information about the process   
    - File descriptors 0,1,2 are stdin, stdout, and stderror respectively
    - File perms - R = read, W = write, U = read and write
    - Capital CRON means the cron job is actively running
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Day 8
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Windows Artifacts, Auditing, and Logging:
    - Getting your user SID - 'get-wmiobject win32_useraccount | select name,sid' or 'get-localuser | select name,sid' or 
      (cmdline) 'wmic useraccount get name,sid'
    - UserAssist:
      - Tracks the GUI-based programs that were run by a specific user
      - To view .exe files run: 'Get-ItemProperty 'REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count''
      - To view shortcut files run: 'Get-ItemProperty 'REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count''
    - Windows BAM:
      - BAM controls activictuy of background locations - the keys are loated in 'Get-Itemproperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*' (
        Windows 1709 & 1803.' or in 'Get-Itemproperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings\*' (Windows 1809 and newer)'
      - Or you can just run winver
    - Recycle Bin:
      - The recycle bin is a huge file. Check it using 'gci 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select *' and 'gci 'C:\$RECYCLE.BIN' -Recurse -Force'
      - Use 'get-childitem "C:\$Recycle.Bin" -force -recures | foreach-object { if (($_.name).startswith(['$R' or '$I'])) { Write-host "$_" -nonewline; 
        write-host " --> " -foregroundcolor green -nonewline ; write-host $(get-content $_.fullname) } }' to see the names of deleted files in recycle bin
    - Prefetch:
      - Prefetch files are created when an application is run from a specific location for the first time. Speeds up the starting processes for applications
      - Use 'gci -Path 'C:\Windows\Prefetch' -ErrorAction Continue | select * | select -first 5' to get
    - Jump Lists:
      - Jump Lists allow users to easily access items they frequently use
      - 'gci -Recurse C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction Continue | select FullName, LastAccessTime' shows applications on the Jump List
    - Recent Files:
      - Registry key that will track the last files and folders opened. Will track the last 150 files or folders opened.
      - gci 'REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' will list files in recent docs
      - '[System.Text.Encoding]::Unicode.GetString((gp "REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt").
        "[property number]")' will convert file hex to unicode 
      - 'Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" | select -Expand property | 
        ForEach-Object { [System.Text.Encoding]::Default.GetString((Get-ItemProperty 
        -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" -Name $_).$_)}' will convert all of a users values
        from text to unicode
    - Browser Artifacts:
