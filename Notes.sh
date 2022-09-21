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
