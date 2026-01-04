## Local Malware triage with Python and MISP platform

When encountering a file suspected of being malicious, the first step is usually to upload it to a platform such as VirusTotal for initial screening. 
If the file's hash is known or if it has a known signature, the link to other malware will be quickly established, saving the analyst time in characterizing the threat. 

However, this approach has its disadvantages. Sharing the binary of a suspicious file with a public community may alert potential attackers that their malware has been detected and is being analyzed. 
Furthermore, the binary itself may contain critical information if it uses private data related to the victim or exploits zero-day vulnerabilities linked to an application developed by the victim.

MISP is a platform that aims to share information about attacks (events) that have already been carried out using a https://www.misp-project.org/ system. For example, it is possible to set up a local MISP instance using certain databases that are relevant to your context. 
From there, you can search based on an attribute (email, IP address, hash, etc.) to check if there are any occurrences similar to the incident you are experiencing. MISP also offers an API and its integration in Python to enable interactions with other applications (https://github.com/MISP/PyMISP). 


