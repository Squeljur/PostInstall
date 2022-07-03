# GIVE UP GITHUB
I've decided to migrate all of my repo's (including private) to CodeBerg. This repo can be found at https://codeberg.org/Squeljur/PostInstall. **NO FURTHER UPDATES WILL BE ADDED HERE**.


Note: we encourage you to add the below to your existing `README.md` on your GitHub project.

== We're Using GitHub Under Protest ==

This project is currently hosted on GitHub.  This is not ideal; GitHub is a
proprietary, trade-secret system that is not Free and Open Souce Software
(FOSS).  We are deeply concerned about using a proprietary system like GitHub
to develop our FOSS project.  We have an
[open {bug ticket, mailing list thread, etc.} ](INSERT_LINK) where the
project contributors are actively discussing how we can move away from GitHub
in the long term.  We urge you to read about the
[Give up GitHub](https://GiveUpGitHub.org) campaign from
[the Software Freedom Conservancy](https://sfconservancy.org) to understand
some of the reasons why GitHub is not a good place to host FOSS projects.

If you are a contributor who personally has already quit using GitHub, please
[check this resource](INSERT_LINK) for how to send us contributions without
using GitHub directly.

Any use of this project's code by GitHub Copilot, past or present, is done
without our permission.  We do not consent to GitHub's use of this project's
code in Copilot.

![Logo of the GiveUpGitHub campaign](https://sfconservancy.org/img/GiveUpGitHub.png)


# Postinstall
A powershell script to remove telemetry and other bloatware on Windows (11) (also fixes this ([1](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-30190), [2](https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/)) Microsoft Office vulnerability), as well as making a few other tweaks such as disabling the new context menu. 

**This script is tested on multiple computers and a VM, all running Windows 11 Pro or Home. Use at own risk**

I recommend running this script on a fresh install of Windows 11. Otherwise make sure to backup your important files/data!

This script is based on a few scripts and commands found over the internet/github. A full list of credits can be found [here](https://github.com/Squeljur/WindowsPostinstall/blob/main/CREDITS.md).

# How to run PostInstall.ps1?
- Download the latest version of the .ps1 file [here](https://github.com/Squeljur/Postinstall/releases), or download and extract the source code zip from the homepage/releases page (pretty much the same thing lol).
- Right click the .ps1 and select ''Run with PowerShell''. 
- You may or may not get the promt to change the [Windows Execution Policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2). (`Set-ExecutionPolicy Unrestricted`)
- You will get two promts asking to remove the children files of "...\Services\edgeupdate" and "...\Services\edgeupdatem", just press enter twice and confirm the deletion
- Wait untill the script is finished... and exit PowerShell.
- Restart the pc (or kill explorer.exe >:))

*thank you myself, for being an idiot*
