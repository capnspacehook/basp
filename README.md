# BASP
## Better Application Security Policy

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/d7d090fa8cd249ef92bb0139b824038f)](https://www.codacy.com/app/capnspacehook/Better-Application-Security-Policy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=capnspacehook/Better-Application-Security-Policy&amp;utm_campaign=Badge_Grade)

A work in progress software restriction policy manager that will make managing your software restriction policies fast and easy. This project was born out of the desire to create a software restriction policy manager that will work on all supported versions and editions of Windows. Microsoft has moved to use Applocker instead of the Software Restriction Policy interface, and Applocker is only available on the Ultimate and Enterprise editions of Windows. So users of more affordable editions of Windows looking to create and manage software restriction policies are out of luck. That is unless you're willing to manually select each and every file you want to include in your policy through Group Policy Manager, if your computer has it.

Well, no more. Now with this tool, files and directories can be whitelisted or blacklisted in a single command. It doesn't matter what version or edition of Windows you're running, as long as you aren't using XP (if you are please upgrade now. It's worth it I promise.). Rule creation, maintainance, monitoring and removal are made simple with this program.

Current features:
* Recursive rule creation for single files and all files within directories
* Can scan for changes in files and update rules accordingly 
* Easy removal of rules
* Secure password protection of tool
* Stores and encrypts a backup of policy settings and rules from the Windows registry
* Can scan for changes or errors of rules in registry and automatically fix them
* Can dynamicaly whitelist, allowing a blacklisted program to run temporarily
* Alerts user if global policy settings were changed and reapplies appropriate settings
* Drops dangerous and unneeded privilges
* Single binary, no external dependencies

Goals of project:
* Compatibility on all versions and editions of Windows from Vista up
* A secure and stable program
* Fast and easy creation and management of hash rules
* Painless management of a secure policy that includes DLLs in it's scope
* Monitor SRP registry keys

As stated above, this project is still a work in progress, so any thoughts, comments or constructive criticism is greatly appreciated. Please let me know if you have any ideas for the project, or some suggestions for improvement. If you want to try BASP out, just download and run the executable from the 'Beta Binaries' folder in Powershell or Command Prompt.
