# Better-Application-Security-Policy

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/d7d090fa8cd249ef92bb0139b824038f)](https://www.codacy.com/app/capnspacehook/Better-Application-Security-Policy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=capnspacehook/Better-Application-Security-Policy&amp;utm_campaign=Badge_Grade)

A work in progress software restriction policy manager that will make managing your software restriction policies fast and easy. This project was born out of the desire to create a software restriction policy manager that will work on all supported versions and editions of Windows. Though Microsoft has depreciated Software Restriction Policy in favor of Applocker, Applocker is only available on Professional and Enterprise editions of Windows. So users of more affordable editions of Windows looking to create and manage software restriction policies are out of luck.

Well, no more. Now with this tool, files and directories can be whitelisted or blacklisted in a single command. It doesn't matter what version or edition of Windows you're running, as long as you aren't using XP (if you are please upgrade now. It's worth it I promise.). Rule creation, maintainance and removal are made simple with this program. 

Current features:
* Recursive rule creation for single files and all files within directories
* Easy removal of rules
* Secure password protection of tool
* Encrypted settings file stores policy settings and rules separate from the Windows registry
* Dynamic whitelisting, ie. allowing a blacklisted program for one launch only
* Alerts user if global policy settings were changed and reapplies appropriate settings

Goals of project:
* Compatibility on all versions and editions of Windows from Vista up
* Fast and easy creation and management of hash rules
* Painless management of a secure policy that includes DLLs in it's scope
* Monitor SRP registry keys
* Monitor policy events in real time

As stated above, this project is still a work in progress, so any thoughts, comments or constructive criticism is greatly appreciated. Please let me know if you have any ideas for the project, or some suggestions for improvement. If you want to test it out, just run the binary in the 'Release' folder in Powershell or Command Prompt. A menu will show you what options are available and how to use them. But don't take my word for it; compile it yourself! 
Note: you will need to compile and link Crypto++ within Visual Studio or whatever compiler you use when compiling. 
