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
 -------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Day 5
 -------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Linux Boot Process:
    - Big Mike Got Killed In Russia - BIOS, MBR, GRUB, Kernel, Init, RunLevels
    - 'lsblk' - shows devices currently being used
    - 'sudo xxd -l 512 -g 1 /dev/sda' - checks tthe contents of the MBR
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
        System5:
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
      - Runlevel0.target - 
