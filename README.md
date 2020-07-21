# dazzleUP

<p align="center"><img src="https://raw.githubusercontent.com/hlldz/dazzleUP/master/images/dazzleUP.png" alt="dazzleUP" width="300"></p>

A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems. dazzleUP detects the following vulnerabilities.

## Exploit Checks

The first feature of dazzleUP is that it uses Windows Update Agent API instead of WMI (like others) when finding missing patches. dazzleUP checks the following vulnerabilities.

* DCOM/NTLM Reflection (Rotten/Juicy Potato) Vulnerability
* CVE-2019-0836
* CVE-2019-0841
* CVE-2019-1064
* CVE-2019-1130
* CVE-2019-1253
* CVE-2019-1385
* CVE-2019-1388
* CVE-2019-1405
* CVE-2019-1315
* CVE-2020-0787
* CVE-2020-0796

dazzleUP do exploit checks when target system is Windows 10 operating system (builds 1809, 1903, 1909 and 2004) that are currently supported by Microsoft. If run on an unsupported operating system; dazzleUP will warn you as "Target system build number is not supported by dazzleUP, passing missing updates controls ...".

## Misconfiguration Checks

dazzleUP performs the following misconfiguration checks for each Windows operating system.

* Always Install Elevated
* Credential enumaration from Credential Manager
* McAfee's SiteList.xml Files
* Modifiable binaries saved as Registry AutoRun
* Modifiable Registry AutoRun Keys
* Modifiable Service Binaries
* Modifiable Service Registry Key
* %PATH% values for DLL Hijack
* Unattended Install Files
* Unquoted Service Paths

## Operational Usage - 1
You can use dazzleUP directly using standalone .EXE and get the results. The screenshot is given below.
<p align="center"><img src="https://raw.githubusercontent.com/hlldz/dazzleUP/master/images/standalone_execution.png" alt="dazzleUP" width="600"></p>

## Operational Usage - 2
You can use dazzleUP directly using Reflective DLL version on Cobalt Strike's Beacon using `dazzleUP.cna` file. The screenshot is given below. For more information; https://www.cobaltstrike.com/aggressor-script/index.html
<p align="center"><img src="https://raw.githubusercontent.com/hlldz/dazzleUP/master/images/beacon_execution.png" alt="dazzleUP" width="600"></p>

