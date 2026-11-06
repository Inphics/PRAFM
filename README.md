 <div align="center">

# PRAFM

### PRIVACY RISK ASSESSMENT FOR MOBILE APPLICATIONS

**MOBILE PRIVACY & SECURITY**

`Python` · `VirusTotal API` · `Android Permissions` · `Privacy Engineering`

---

**An automated, permission-based approach to exploring privacy-related risks in Android applications.**

</div>

## Project Overview

PRAFM (Privacy Risk Assessment for Mobile Applications) is a Python-based tool designed to examine the permissions declared by Android applications and organise them into privacy-relevant categories.

The tool retrieves application information using the VirusTotal API, extracts declared Android permissions, and analyses their characteristics using Android Open Source Project (AOSP) permission metadata and Android developer documentation.

The aim is to make permission-related privacy indicators easier to identify, interpret and compare.

## Key Features

- **Application metadata retrieval** – Uses the VirusTotal API to retrieve Android application information based on predefined SHA-256 hashes.
- **Permission extraction** – Recursively identifies permissions declared in the retrieved application data.
- **Permission classification** – Uses permission definitions, protection levels and predefined rules to distinguish user-visible and user-hidden permissions.
- **Privacy categorisation** – Groups permissions into three categories:
  - **Core Privacy Classification**
  <p>
    <img src="https://img.shields.io/badge/PII-Personally%20Identifiable%20Information-2563EB?style=for-the-badge" alt="PII - Blue"/>
  </p>

  Permissions potentially associated with personally identifiable or sensitive user information.

  <p>
    <img src="https://img.shields.io/badge/Digital-Digital%20Information%20%26%20Functionality-16A34A?style=for-the-badge" alt="Digital - Green"/>
  </p>

  Permissions associated with digital information, services and device functionality.

  <p>
    <img src="https://img.shields.io/badge/Cyberphysical-Physical%20Device%20%26%20Environment%20Interaction-EA580C?style=for-the-badge" alt="Cyberphysical - Orange"/>
  </p>

  Permissions associated with physical device capabilities and interactions with the surrounding environment.
  
- **Permission descriptions** – Retrieves relevant descriptions from AOSP and Android developer documentation.
- **Uncertainty logging** – Records permissions that cannot be confidently categorised for further review.
- **CSV reporting** – Exports the analysis into a structured CSV file for further inspection.

## Methodology

PRAFM follows a permission-based analysis workflow:

1. **Application identification**  
   Predefined SHA-256 hashes are used to retrieve Android application metadata through VirusTotal.

2. **Permission extraction**  
   The tool recursively searches the retrieved JSON data for declared Android permissions.

3. **Permission metadata retrieval**  
   Permission definitions, groups, descriptions and protection levels are collected from AOSP and Android developer documentation.

4. **Visibility classification**  
   Permissions are classified as user-visible or user-hidden using predefined permission lists and protection-level heuristics.

5. **Privacy categorisation**  
   Permissions are assigned to PII, Digital or Cyberphysical categories using explicit mappings, Android permission groups, documentation metadata and keyword-based heuristics.

6. **Report generation**  
   Results are exported to CSV, while uncertain classifications are recorded separately for manual review.

## Output

The tool generates two main output files:

| File | Description |
|---|---|
| `permissions_report.csv` | Structured report containing application and permission information, protection levels, visibility classifications and privacy categories. |
| `uncertain_permissions_log.txt` | Log of permissions that could not be confidently categorised. |

The CSV report contains the following fields:

- Total Permissions
- Package
- Permission
- Protection Level
- Description
- User Visibility
- Category

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3 | Core implementation |
| VirusTotal API | Android application metadata retrieval |
| Requests | HTTP requests |
| BeautifulSoup | HTML documentation parsing |
| XML ElementTree | XML parsing of AOSP permission metadata |
| JSON | Processing VirusTotal responses |
| CSV | Exporting analysis results |
| Regular Expressions | Text and permission processing |

## Requirements

- Python 3
- A VirusTotal API key
- Internet connection

Install the required Python packages:

```bash
pip install requests beautifulsoup4
```

## Getting Started

1.
