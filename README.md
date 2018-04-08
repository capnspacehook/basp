# BASP
## Better Application Security Policy

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/d7d090fa8cd249ef92bb0139b824038f)](https://www.codacy.com/app/capnspacehook/Better-Application-Security-Policy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=capnspacehook/Better-Application-Security-Policy&amp;utm_campaign=Badge_Grade)

A work in progress software restriction policy manager that will make managing your software restriction policies fast and easy. This project was born out of the desire to create a software restriction policy manager that will work on all supported versions and editions of Windows. Microsoft has moved to use Applocker instead of the Software Restriction Policy interface, and Applocker is only available on the Ultimate and Enterprise editions of Windows. So users of more affordable editions of Windows looking to create and manage software restriction policies are out of luck. That is unless you're willing to manually select each and every file you want to include in your policy through Group Policy Manager, if your computer has it.

Well, no more. Now with BASP, files and directories can be whitelisted or blacklisted in a single command. It doesn't matter what version or edition of Windows you're running. Windows XP and Windows Server 2003 are even supported on the 'XP Compatibility' branch. BASP makes software restriction rule creation, maintainance, monitoring, and integrity checking simple and secure on every Windows system since 2001.

Current features:
* Recursive rule creation for single files and all files within directories
* Can scan for changes in files and update rules accordingly 
* Runs on every version and edition of Windows since Windows XP and Windows Server 2003
* Easy removal of rules
* Secure password protection of tool
* Stores and encrypts a backup of policy settings and rules from the Windows registry
* Can scan for changes or errors of rules in registry and automatically correct them and remove extra maliciously added rules
* Can temporarily whitelist a blacklisted file, allowing only admins that can authenticate with BASP to run blacklisted programs
* Alerts user if global policy settings were changed and reapplies appropriate settings
* Drops dangerous and unneeded privilges
* Automatically whitelists itself upon first run
* Single binary, no external dependencies

As stated above, this project is still a work in progress, so any thoughts, comments or constructive criticism is greatly appreciated. Please let me know if you have any ideas for the project, or some suggestions for improvement. If you want to try BASP out, just download and run the executable from the 'Beta Binaries' folder in Powershell or Command Prompt.

If you don't trust the executable, and you shouldn't (you don't know who I am most likely), check the [VirusTotal Scan](https://www.virustotal.com/#/file/6368308749ca46140722d2ac92dc2715454cd7e229abf6960976b2f656e470f5/detection), or better compile BASP from source. BASP was written and built with Visual Studio 2017, so just import the solution file and clone the below repos and you should be up and running in no time.

## Credits

Crypto++  
Compilation Copyright (c) 1995-2018 by Wei Dai  
https://github.com/weidai11/cryptopp

ConcurrentQueue  
Copyright (c) 2013-2018 by Cameron Desrochers  
https://github.com/cameron314/concurrentqueue

WinReg  
Copyright (c) 2017 by Giovanni Dicanio  
https://github.com/GiovanniDicanio/WinReg

Clara  
Copyright (c) 2014-2018 by Phil Nash  
https://github.com/catchorg/Clara
