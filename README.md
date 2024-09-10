# Cybersecurity-Threat-Detection-System
Table of Contents
Threat Detection and Hunting
Tools
Alerting Engine
Endpoint Monitoring
Network Monitoring
Fingerprinting Tools
DataSet
Resources
Frameworks
DNS
Command and Control
Osquery
Windows
Sysmon
PowerShell
Fingerprinting
Research Papers
Blogs
Videos
Trainings
Twitter
Threat Simulation
Tools
Resources
Contribute
License
Threat Detection and Hunting
Tools
MITRE ATT&CK Navigator(source code) - The ATT&CK Navigator is designed to provide basic navigation and annotation of ATT&CK matrices, something that people are already doing today in tools like Excel.
HELK - A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.
osquery-configuration - A repository for using osquery for incident detection and response.
DetectionLab - Vagrant & Packer scripts to build a lab environment complete with security tooling and logging best practices.
Sysmon-DFIR - Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
sysmon-config - Sysmon configuration file template with default high-quality event tracing.
sysmon-modular - A repository of sysmon configuration modules. It also includes a mapping of Sysmon configurations to MITRE ATT&CK techniques.
Revoke-Obfuscation - PowerShell Obfuscation Detection Framework.
Invoke-ATTACKAPI - A PowerShell script to interact with the MITRE ATT&CK Framework via its own API.
Unfetter - A reference implementation provides a framework for collecting events (process creation, network connections, Window Event Logs, etc.) from a client machine and performing CAR analytics to detect potential adversary activity.
Flare - An analytical framework for network traffic and behavioral analytics.
RedHunt-OS - A Virtual Machine for Adversary Emulation and Threat Hunting. RedHunt aims to be a one stop shop for all your threat emulation and threat hunting needs by integrating attacker's arsenal as well as defender's toolkit to actively identify the threats in your environment.
Oriana - Lateral movement and threat hunting tool for Windows environments built on Django comes Docker ready.
Bro-Osquery - Bro integration with osquery
Brosquery - A module for osquery to load Bro logs into tables
DeepBlueCLI - A PowerShell Module for Hunt Teaming via Windows Event Logs
Uncoder - An online translator for SIEM saved searches, filters, queries, API requests, correlation and Sigma rules
Sigma - Generic Signature Format for SIEM Systems
CimSweep - A suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows
Dispatch - An open-source crisis management orchestration framework
EQL - Event Query Language
EQLLib - The Event Query Language Analytics Library (eqllib) is a library of event based analytics, written in EQL to detect adversary behaviors identified in MITRE ATT&CK™.
BZAR (Bro/Zeek ATT&CK-based Analytics and Reporting) - A set of Zeek scripts to detect ATT&CK techniques
Security Onion - An open-source Linux distribution for threat hunting, security monitoring, and log management. It includes ELK, Snort, Suricata, Zeek, Wazuh, Sguil, and many other security tools
Varna - A quick & cheap AWS CloudTrail Monitoring with Event Query Language (EQL)
BinaryAlert - Serverless, real-time & retroactive malware detection
hollows_hunter - Scans all running processes, recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches).
ThreatHunting - A Splunk app mapped to MITRE ATT&CK to guide your threat hunts
Sentinel Attack - A repository of Azure Sentinel alerts and hunting queries leveraging sysmon and the MITRE ATT&CK framework
Brim - A desktop application to efficiently search large packet captures and Zeek logs
YARA - The pattern matching swiss knife
Intel Owl - An Open Source Intelligence, or OSINT solution to get threat intelligence data about a specific file, an IP or a domain from a single API at scale.
Capa - An open-source tool to identify capabilities in executable files.
Alerting Engine
ElastAlert - A framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch
StreamAlert - A serverless, realtime data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using datasources and alerting logic you define
Endpoint Monitoring
osquery (github) - SQL powered operating system instrumentation, monitoring, and analytics
Kolide Fleet - A flexible control server for osquery fleets
Zeek Agent - An endpoint monitoring agent that provides host activity to Zeek
Velociraptor - Endpoint visibility and collection tool
Sysdig - A tool for deep Linux system visibility, with native support for containers. Think about sysdig as strace + tcpdump + htop + iftop + lsof + ...awesome sauce
go-audit - An alternative to the Linux auditd daemon
Sysmon - A Windows system service and device driver that monitors and logs system activity to the Windows event log
OSSEC - An open-source Host-based Intrusion Detection System (HIDS)
WAZUH - An open-source security platform
Network Monitoring
Zeek (formerly Bro) - A network security monitoring tool
ntopng - A web-based network traffic monitoring tool
Suricata - A network threat detection engine
Snort (github) - A network intrusion detection tool
Joy - A package for capturing and analyzing network flow data and intraflow data, for network research, forensics, and security monitoring
Netcap - A framework for secure and scalable network traffic analysis
Moloch - A large scale and open source full packet capture and search tool
Stenographer - A full-packet-capture tool
Fingerprinting Tools
JA3 - A method for profiling SSL/TLS Clients and Servers
HASSH - Profiling Method for SSH Clients and Servers
RDFP - Zeek Remote desktop fingerprinting script based on FATT (Fingerprint All The Things)
FATT - A pyshark based script for extracting network metadata and fingerprints from pcap files and live network traffic
FingerprinTLS - A TLS fingerprinting method
Mercury - Network fingerprinting and packet metadata capture
GQUIC Protocol Analyzer for Zeek
Recog - A framework for identifying products, services, operating systems, and hardware by matching fingerprints against data returned from various network probes
Hfinger - Fingerprinting HTTP requests
JARM - An active Transport Layer Security (TLS) server fingerprinting tool.
Dataset
Mordor - Pre-recorded security events generated by simulated adversarial techniques in the form of JavaScript Object Notation (JSON) files. The data is categorized by platforms, adversary groups, tactics and techniques defined by the Mitre ATT&CK Framework.
SecRepo.com(github repo) - Samples of security related data.
Boss of the SOC (BOTS) Dataset Version 1
Boss of the SOC (BOTS) Dataset Version 2
Boss of the SOC (BOTS) Dataset Version 3
EMBER (paper) - The EMBER dataset is a collection of features from PE files that serve as a benchmark dataset for researchers
theZoo - A repository of LIVE malwares
CIC Datasets - Canadian Institute for Cybersecurity datasets
Netresec's PCAP repo list - A list of public packet capture repositories, which are freely available on the Internet.
PCAP-ATTACK - A repo of PCAP samples for different ATT&CK techniques.
EVTX-ATTACK-SAMPLES - A repo of Windows event samples (EVTX) associated with ATT&CK techniques (EVTX-ATT&CK Sheet).
Resources
Huntpedia - Your Threat Hunting Knowledge Compendium
Hunt Evil - Your Practical Guide to Threat Hunting
The Hunter's Handbook - Endgame's guide to adversary hunting
ThreatHunter-Playbook - A Threat hunter's playbook to aid the development of techniques and hypothesis for hunting campaigns.
The ThreatHunting Project - A great collection of hunts and threat hunting resources.
CyberThreatHunting - A collection of resources for threat hunters.
Hunt-Detect-Prevent - Lists of sources and utilities to hunt, detect and prevent evildoers.
Alerting and Detection Strategy Framework
Generating Hypotheses for Successful Threat Hunting
Expert Investigation Guide - Threat Hunting
Active Directory Threat Hunting
Threat Hunting for Fileless Malware
Windows Commands Abused by Attackers
Deception-as-Detection - Deception based detection techniques mapped to the MITRE’s ATT&CK framework.
On TTPs
Hunting On The Cheap (Slides)
Threat Hunting Techniques - AV, Proxy, DNS and HTTP Logs
Detecting Malware Beacons Using Splunk
Data Science Hunting Funnel
Use Python & Pandas to Create a D3 Force Directed Network Diagram
Syscall Auditing at Scale
Catching attackers with go-audit and a logging pipeline
The Coventry Conundrum of Threat Intelligence
Signal the ATT&CK: Part 1 - Building a real-time threat detection capability with Tanium that focuses on documented adversarial techniques.
SANS Summit Archives (DFIR, Cyber Defense) - Threat hunting, Blue Team and DFIR summit slides
Bro-Osquery - Large-Scale Host and Network Monitoring Using Open-Source Software
Malware Persistence - Collection of various information focused on malware persistence: detection (techniques), response, pitfalls and the log collection (tools).
Threat Hunting with Jupyter Notebooks
How Dropbox Security builds tools for threat detection and incident response
Introducing Event Query Language
The No Hassle Guide to Event Query Language (EQL) for Threat Hunting (PDF)
Introducing the Funnel of Fidelity (PDF)
Detection Spectrum (PDF)
Capability Abstraction (PDF)
Awesome YARA - A curated list of awesome YARA rules, tools, and resources
Defining ATT&CK Data Sources - A two-part blog series that outlines a new methodology to extend ATT&CK’s current data sources.
Frameworks
MITRE ATT&CK - A curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s lifecycle and the platforms they are known to target.
MITRE CAR - The Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the Adversary Tactics, Techniques, and Common Knowledge (ATT&CK™) adversary model.
Alerting and Detection Strategies Framework - A framework for developing alerting and detection strategies.
A Simple Hunting Maturity Model - The Hunting Maturity Model describes five levels of organizational hunting capability, ranging from HMM0 (the least capability) to HMM4 (the most).
The Pyramic of Pain - The relationship between the types of indicators you might use to detect an adversary's activities and how much pain it will cause them when you are able to deny those indicators to them.
A Framework for Cyber Threat Hunting
The PARIS Model - A model for threat hunting.
Cyber Kill Chain - It is part of the Intelligence Driven Defense® model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.
The DML Model - The Detection Maturity Level (DML) model is a capability maturity model for referencing ones maturity in detecting cyber attacks.
NIST Cybersecurity Framework
OSSEM (Open Source Security Events Metadata) - A community-led project that focuses on the documentation and standardization of security event logs from diverse data sources and operating systems
MITRE Shield - A knowledge base of active defense techniques and tactics (Active Defense Matrix)
DNS
Detecting DNS Tunneling
Hunting the Known Unknowns (with DNS)
Detecting dynamic DNS domains in Splunk
Random Words on Entropy and DNS
Tracking Newly Registered Domains
Suspicious Domains Tracking Dashboard
Proactive Malicious Domain Search
DNS is NOT Boring - Using DNS to Expose and Thwart Attacks
Actionable Detects - Blue Team Tactics
Command and Control
Rise of Legitimate Services for Backdoor Command and Control
Watch Your Containers - A malware using DogeCoin based DGA to generate C2 domain names.
DoH
Hiding in Plain Sight - A malware abusing Google DoH
All the DoH - A Twitter thread on malware families and utilities that use DNS-over-HTTPS.
Osquery
osquery Across the Enterprise
osquery for Security — Part 1
osquery for Security — Part 2 - Advanced osquery functionality, File integrity monitoring, process auditing, and more.
Tracking a stolen code-signing certificate with osquery
Monitoring macOS hosts with osquery
Kolide's Blog
The osquery Extensions Skunkworks Project
Windows
Threat Hunting via Windows Event Logs
Windows Logging Cheat Sheets
Active Directory Threat Hunting
Windows Hunting - A collection of Windows hunting queries
Windows Commands Abused by Attackers
JPCERT - Detecting Lateral Movement through Tracking Event Logs
Tool Analysis Result Sheet
Sysmon
Splunking the Endpoint: Threat Hunting with Sysmon
Hunting with Sysmon
Threat Hunting with Sysmon: Word Document with Macro
Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK
Part I (Event ID 7)
Part II (Event ID 10)
Advanced Incident Detection and Threat Hunting using Sysmon (and Splunk) (botconf 2016 Slides, FIRST 2017 Slides)
The Sysmon and Threat Hunting Mimikatz wiki for the blue team
Splunkmon — Taking Sysmon to the Next Level
Sysmon Threat Detection Guide (PDF)
PowerShell
Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science (Paper, Slides)
Hunting the Known Unknowns (With PowerShell)
HellsBells, Let's Hunt PowerShells!
Hunting for PowerShell Using Heatmaps
Fingerprinting
JA3: SSL/TLS Client Fingerprinting for Malware Detection
TLS Fingerprinting with JA3 and JA3S
HASSH - a profiling method for SSH Clients and Servers
HASSH @BSides Canberra 2019 - Slides
Finding Evil on the Network Using JA3/S and HASSH
RDP Fingerprinting - Profiling RDP Clients with JA3 and RDFP
Effective TLS Fingerprinting Beyond JA3
TLS Fingerprinting in the Real World
HTTP Client Fingerprinting Using SSL Handshake Analysis (source code: mod_sslhaf
TLS fingerprinting - Smarter Defending & Stealthier Attacking
JA3er - a DB of JA3 fingerprints
An Introduction to HTTP fingerprinting
TLS Fingerprints collected from the University of Colorado Boulder campus network
The use of TLS in Censorship Circumvention
TLS Beyond the Browser: Combining End Host and Network Data to Understand Application Behavior
HTTPS traffic analysis and client identification using passive SSL/TLS fingerprinting
Markov Chain Fingerprinting to Classify Encrypted Traffic
HeadPrint: Detecting Anomalous Communications through Header-based Application Fingerprinting
Research Papers
Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains
The Diamond Model of Intrusion Analysis
EXPOSURE: Finding Malicious Domains Using Passive DNS Analysis
A Comprehensive Approach to Intrusion Detection Alert Correlation (Paper, Dissertation)
On Botnets that use DNS for Command and Control
Intelligent, Automated Red Team Emulation
Machine Learning for Encrypted Malware Traffic Classification
Blogs
David Bianco's Blog
DFIR and Threat Hunting Blog
CyberWardog's Blog (old)
Chris Sanders' Blog
Kolide Blog
Videos
SANS Threat Hunting and IR Summit 2017
SANS Threat Hunting and IR Summit 2016
BotConf 2016 - Advanced Incident Detection and Threat Hunting using Sysmon and Splunk
BSidesCharm 2017 - Detecting the Elusive: Active Directory Threat Hunting
BSidesAugusta 2017 - Machine Learning Fueled Cyber Threat Hunting
Toppling the Stack: Outlier Detection for Threat Hunters
BSidesPhilly 2017 - Threat Hunting: Defining the Process While Circumventing Corporate Obstacles
Black Hat 2017 - Revoke-Obfuscation: PowerShell Obfuscation Detection (And Evasion) Using Science
DefCon 25 - MS Just Gave the Blue Team Tactical Nukes
BSides London 2017 - Hunt or be Hunted
SecurityOnion 2017 - Pivoting Effectively to Catch More Bad Guys
SkyDogCon 2016 - Hunting: Defense Against The Dark Arts
BSidesAugusta 2017 - Don't Google 'PowerShell Hunting'
BSidesAugusta 2017 - Hunting Adversaries w Investigation Playbooks & OpenCNA
Visual Hunting with Linked Data
RVAs3c - Pyramid of Pain: Intel-Driven Detection/Response to Increase Adversary's Cost
BSidesLV 2016 - Hunting on the Endpoint w/ Powershell
Derbycon 2015 - Intrusion Hunting for the Masses A Practical Guide
BSides DC 2016 - Practical Cyborgism: Getting Start with Machine Learning for Incident Detection
SANS Webcast 2018 - What Event Logs? Part 1: Attacker Tricks to Remove Event Logs
Profiling And Detecting All Things SSL With JA3
ACoD 2019 - HASSH SSH Client/Server Profiling
QueryCon 2018 - An annual conference for the osquery open-source community (querycon.io)
Visual Hunting with Linked Data Graphs
SecurityOnion Con 2018 - Introduction to Data Analysis
Trainings
SANS SEC555 - SIEM with Tactical Analytics.
SpecterOps Adversary Tactics: PowerShell (FREE)
SpecterOps Adversary Tactics: Detection
eLearnSecurity THP - Threat Hunting Professional
Twitter
"Awesome Detection" Twitter List - Security guys who tweet about threat detection, hunting, DFIR, and red teaming
Threat Simulation 
A curated list of awesome adversary simulation resources

Tools
MITRE CALDERA - An automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks.
APTSimulator - A Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.
Atomic Red Team - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework.
Network Flight Simulator - flightsim is a lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility.
Metta - A security preparedness tool to do adversarial simulation.
Red Team Automation (RTA) - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.
SharpShooter - Payload Generation Framework.
CACTUSTORCH - Payload Generation for Adversary Simulations.
DumpsterFire - A modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events.
Empire(website) - A PowerShell and Python post-exploitation agent.
PowerSploit - A PowerShell Post-Exploitation Framework.
RedHunt-OS - A Virtual Machine for Adversary Emulation and Threat Hunting. RedHunt aims to be a one stop shop for all your threat emulation and threat hunting needs by integrating attacker's arsenal as well as defender's toolkit to actively identify the threats in your environment.
Infection Monkey - An open source Breach and Attack Simulation (BAS) tool that assesses the resiliency of private and public cloud environments to post-breach attacks and lateral movement.
Splunk Attack Range - A tool that allows you to create vulnerable instrumented local or cloud environments to simulate attacks against and collect the data into Splunk.
Resources
MITRE's Adversary Emulation Plans
Awesome Red Teaming - A list of awesome red teaming resources
Red-Team Infrastructure Wiki - Wiki to collect Red Team infrastructure hardening resources.
Payload Generation using SharpShooter
SpecterOps Blog
Threat Hunting
Advanced Threat Tactics - A free course on red team operations and adversary simulations.
Signal the ATT&CK: Part 1 - Modelling APT32 in CALDERA
Red Teaming/Adversary Simulation Toolkit - A collection of open source and commercial tools that aid in red team operations.
C2 Matrix (Google Sheets)
