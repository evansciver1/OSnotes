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
  - ($profile | get-member -membertype noteproperty).name | foreach-object { if ((test-path $PROFILE.$_) -eq $true) { write-host "$PROFILE.$_" -foregroundcolor green -nonewline ; write-host "exists }}
    getss user profiles and confirms they exist
  - Remoting:
    - requires windows remote management to be running [winrm]
    - get-item wsman:\localhost\client\trustedhosts shows what computers are trusted to remote in; by default only allows one addition
    - using quotes around what you want to add w/get-item allows multiple additions i.e. ... -value "10.20.30.40,not_kremlin.ru" will add both
    - 'invoke-command' also works to temporarily remote in i.e. 'Invoke-Command -ComputerName File-Server {Get-Service}'
    - using -asjob while querying a large number of hosts or data requires the recieve-job command to be run after 
    
