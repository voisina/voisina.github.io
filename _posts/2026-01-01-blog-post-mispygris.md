# misPYgris, a local malware triage tool developed in Python, integrated to MISP platform

When encountering a file suspected of being malicious, the first step is usually to upload it to a platform such as VirusTotal for initial screening. 
If the file's hash is known or if it has a known signature, the link to other malware will be quickly established, saving the analyst time in characterizing the threat. 

However, this approach has its disadvantages. Sharing the binary of a suspicious file with a public community may alert potential attackers that their malware has been detected and is being analyzed. 
Furthermore, the binary itself may contain critical information if it uses private data related to the victim or exploits zero-day vulnerabilities linked to an application developed by the victim.

MISP is a platform that aims to share information about attacks (events) that have already been carried out using a community sharing system (https://www.misp-project.org/). For example, it is possible to set up a local MISP instance using certain databases that are relevant to your context. 
From there, you can search based on an attribute (email, IP address, hash, etc.) to check if there are any occurrences similar to the incident you are experiencing. MISP also offers an API and its integration in Python to enable interactions with other applications (https://github.com/MISP/PyMISP). 

The objective of the MISPYGRIS project is to perform an initial triage by extracting metadata from a suspicious binary file (such as the file hash, the names of the PE sections, their size, and their entropy level), but also to use the printable character strings contained in the binary to populate an artifact file that would then be used to perform searches in a local instance of MISP. 

In this article, I will briefly present the features and how works MISPYGRIS, highlighting its strengths and limitations.

### Installation

MISPYGRIS is a Python3 application that requires two dependencies: pymisp and pefile. 

```bash
git clone https://github.com/voisina/mispygris.git
cd mispygris
python3 -m venv venv && . venv/bin/activate
pip install pymisp pefile
```

Once installed, you can test its functionality by displaying the help section:

```bash
python3 mispygris.py -h                    
usage: mispygris.py [-h] [-f FILE] -m {populate,query} [-n MIN_LENGTH] [--misp-url MISP_URL] [--misp-key MISP_KEY] [--misp-cert MISP_CERT] [--ioc-file IOC_FILE]

Extract printable strings from binary files and interact with a MISP instance.

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Path to a binary file
  -m, --mode {populate,query}
                        populate: store artifacts, query: check on MISP instance
  -n, --min-length MIN_LENGTH
                        Minimum string length (default: 4)
  --misp-url MISP_URL   MISP instance URL
  --misp-key MISP_KEY   MISP API key
  --misp-cert MISP_CERT
                        SSL certificate
  --ioc-file IOC_FILE   IOC input file for query mode (default: artifacts.txt)

    Examples:
      Extract strings from a single file and populate MISP:
       mispygris.py -f sample.bin -m populate

      Read IOC from a file and query MISP:
       mispygris.py -m query --misp-url https://misp.local --misp-key ABC123 --misp-cert cert.crt

```

### misPYgris Architecture

The architecture of misPYgris is very simple. It consists of the script itself, a file in which the various indicators extracted from a binary are saved, and a MISP instance accessible via its API. There are two modes of operation. A “populate” mode in which indicators are extracted from the binary and saved in the artifacts file. A second “query” mode in which the indicators are read from the artifacts file and used for searching through the MISP API.

For the “populate” mode, misPYgris works in two stages. First, it extracts the metadata from the file passed as an argument. To do this, it uses the pefile () module to retrieve all the sections, their names, sizes, and entropy. It also calculates the file hash for three algorithms. It then writes all this information to a file called “artifacts.txt” by default . For the second phase, it uses a list of regexes defined in the “config.py” file to match all the character strings extracted from the binary file (similar to the “strings” command). Each string for which a match is found is also written to the artifact file. 

Here is an example for a binary file corresponding to Wannacry malware :
```bash
$ python3 mispygris.py -m populate -f malicious.exe
$ cat artifacts.txt

 
# File Information
# --------------------------------------------------
# Path: /home/linux/mispygris/malware_repo/malicious.exe
# 
# File Hashes
# --------------------------------------------------
# MD5     : db349b97c37d22f5ea1d1841e3c89eb4
# SHA1    : e889544aff85ffaf8b0d0da705105dee7c97fe26
# SHA256  : 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
# 
# PE Sections
# --------------------------------------------------
# Section Name : .text
#   Suspicious Section Name : false
#   Unusual Section Name : false
#   Entropy     : 6.1346
#   Suspicious Entropy : false
#   Raw Size    : 36864
#   Virtual Size: 35786
# 
# Section Name : .rdata
#   Suspicious Section Name : false
#   Unusual Section Name : false
#   Entropy     : 3.5036
#   Suspicious Entropy : false
#   Raw Size    : 4096
#   Virtual Size: 2456
# 
# Section Name : .data
#   Suspicious Section Name : false
#   Unusual Section Name : false
#   Entropy     : 6.1003
#   Suspicious Entropy : false
#   Raw Size    : 159744
#   Virtual Size: 3164316
# 
# Section Name : .rsrc
#   Suspicious Section Name : false
#   Unusual Section Name : false
#   Entropy     : 7.9952
#   Suspicious Entropy : true
#   Raw Size    : 3518464
#   Virtual Size: 3515476
# 
md5:db349b97c37d22f5ea1d1841e3c89eb4
sha1:e889544aff85ffaf8b0d0da705105dee7c97fe26
sha256:24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
binary_file:KERNEL32.dll
binary_file:ADVAPI32.dll
binary_file:WS2_32.dll
binary_file:MSVCP60.dll
binary_file:iphlpapi.dll
binary_file:WININET.dll
binary_file:MSVCRT.dll
binary_file:KERNEL32.dll
binary_file:MSVCRT.dll
binary_file:launcher.dll
binary_file:mssecsvc.exe
binary_file:mssecsvc.exe
binary_file:KERNEL32.dll
binary_file:launcher.dll
binary_file:msvcrt.dll
binary_file:msvcrtd.dll
binary_file:msvcrt.dll
binary_file:msvcrtd.dll
binary_file:tasksche.exe
domain:http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
mutex:OpenMutexA
binary_file:KERNEL32.dll
binary_file:USER32.dll
binary_file:ADVAPI32.dll
binary_file:SHELL32.dll
binary_file:OLEAUT32.dll
binary_file:WS2_32.dll
binary_file:MSVCRT.dll
binary_file:MSVCP60.dll
binary_file:advapi32.dll
binary_file:kernel32.dll
binary_file:cmd.exe
mutex:Global\MsWinZonesCacheCounterMutexA
binary_file:tasksche.exe
binary_file:taskdl.exe
binary_file:taskdl.exe
binary_file:taskse.exe
ip:6.0.0.0

```

First, we find the hashes of the binary. You can use one of these hashes to find the binary file used in this example. Information about the different sections in the binary file is also displayed (assuming it is a PE file). This information will not be used to query the MISP API, but it does allow the analyst to determine whether packing or encryption is suspected, as is the case with Wannacry, or whether the resource section contains an encrypted part of the malware. Next, in the format [indicator_type:value], we find the list of strings that have been matched by one of the regexes. In our example, there is a set of .dll files taken from the import list, as well as other binary files with the .exe extension. The URL used by Wannacry as a “killswitch” is also present. An IP address was also found, but this is a false positive. 


For the “query” mode, the artifact file is read and for each non-commented line, the misp.search() function of the pymisp module is used to perform a search through the MISP API on the attributes. 
In order to query the API, you will need to specify the address of the MISP instance, the API key generated for a user, and a certificate that ensures the encryption of the request to the server. Here is an example of a request that will be sent from the previously generated file:

```bash
 python3 mispygris.py -m query --misp-url https://misp.local --misp-key KEY --misp-cert cert.crt 

db349b97c37d22f5ea1d1841e3c89eb4 622 OSINT -  Player 3 Has Entered the Game: Say Hello to 'WannaCry'
e889544aff85ffaf8b0d0da705105dee7c97fe26 622 OSINT -  Player 3 Has Entered the Game: Say Hello to 'WannaCry'
24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c 620 Ransomware spreading through SMB attacking multiple companies
launcher.dll 1262 Buzzing in the Background: BumbleBee, a New Modular Backdoor Evolved From BookWorm
launcher.dll 1262 Buzzing in the Background: BumbleBee, a New Modular Backdoor Evolved From BookWorm
tasksche.exe 623 OSINT - Alert (TA17-132A) Indicators Associated With WannaCry Ransomware
cmd.exe 1048 VMRay Analyzer Report for Sample #252574 (related amf-fr.org)
tasksche.exe 623 OSINT - Alert (TA17-132A) Indicators Associated With WannaCry Ransomware
```

Our research has identified Wannacry using various attributes. The hash was found, as well as the name of one of the binaries extracted from the malware. Other .dll and .exe files were also identified, but these were false positives. However, correlating the results confirms that this is indeed a version similar to Wannacry. It should be noted that only one MISP feed was synchronized in our instance in order to perform our test, namely the default OSINT feed from CIRCL (https://www.circl.lu/doc/misp/feed-osint). 

The main reason for splitting misPYgris's operation into two modes is that MISP is not strictly speaking a malware analysis platform but is “event”-oriented. MISP allows security incidents to be encoded as events. These events are then defined by a set of attributes. By decoupling the extraction of indicators from the binary  from requests to MISP, analysts will be able to enrich the artifacts file with elements of an incident that are not contained in the file, such as the email address linked to a phishing attempt prior to the use of malware. 

### Limitations and discussion

misPYgris has the same limitations as a tool such as “strings” when attempting to extract interesting elements from a binary file. It is sometimes difficult to distinguish real character strings from binary portions falsely identified as such. Regexes can be used to avoid these false positives, but this carries the risk of missing artifacts that are useful for analyzing malware. However, the biggest limitation of our system is that malware that uses obfuscation, packing, or encryption makes analysis much less effective. Future developments of misPYgris could take these techniques into account in order to potentially circumvent them. 

Furthermore, the definition of regexes is essential for the proper functioning of our application. However, only an in-depth study of a large number of malware samples will allow us to identify which artifacts are truly interesting for triage. 

Secondly, the current version of misPYgris uses a very limited portion of the MISP API's functionality. If our tool proves useful, it would be interesting to optimize the calls in order to make them more efficient and improve search performance. In addition, only the PE format is currently supported for metadata extraction. It would obviously be useful to integrate ELF file management. Finally, the quality of the code could be improved, as the focus of this first version is mainly a “proof of concept” to show the value of integrating MISP into a local triage of suspicious binaries. 

However, our initial tests show that it is possible to identify the nature of certain malware using a collaborative platform, without making our samples public, while using open-source tools that can be adapted to the needs and contexts of analysts. 

