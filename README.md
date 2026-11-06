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

## Example Analysis Results

PRAFM has been successfully executed against a collection of Android application SHA-256 hashes, generating permission-based privacy analysis results.

The following files demonstrate the tool's reporting capabilities.

### 📋 Interpreting the Results

The `permissions_report.csv` file provides a structured overview of the permissions declared by the Android applications examined.

Each record includes:

- **Total Permissions** — Number of permissions identified for an application.
- **Package** — Android application package identifier.
- **Permission** — Declared Android permission.
- **Protection Level** — Android permission protection-level metadata.
- **Description** — Permission description.
- **User Visibility** — User-visible or user-hidden classification.
- **Category** — PII, Digital or Cyberphysical classification.

### 📝 Uncertainty Handling

PRAFM also generates `uncertain_permissions_log.txt` to document permissions requiring further classification review.

During the example execution, the uncertainty log was empty, indicating that no uncertain classifications were recorded.

An empty uncertainty log does not independently confirm that every classification is correct. The tool uses predefined rules and heuristic approaches, and some classifications may still require manual validation.

> **Note:** PRAFM analyses declared permission metadata rather than observed application behaviour. The results are intended to support privacy assessment and further investigation, not provide definitive conclusions about an application's privacy practices.

---

**Explore the generated outputs:**

📊 [View Permission Analysis Report](permissions_report.csv (Example))

📝 [View Uncertain Permissions Log](uncertain_permissions_log.txt (Example))

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

1. Clone the repository:

git clone https://github.com/YOUR-USERNAME/PRAFM.git

Navigate into the project directory:

cd PRAFM

Install dependencies:

pip install -r requirements.txt

Configure your VirusTotal API key.

For safer key management, use an environment variable rather than committing your API key to the repository. The script should read it using:

import os

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

Set the environment variable before running the script.

Run the Python script:

python main.py

Review the generated CSV report and uncertainty log.

Project Structure

PRAFM/
│
├── main.py
├── requirements.txt
├── README.md
│
├── outputs/
│   ├── permissions_report.csv
│   └── uncertain_permissions_log.txt
│
└── docs/
    └── methodology.md

The folders shown above are a suggested repository structure. Create them as needed when organising the project.

Scope and Limitations

PRAFM focuses on the analysis of Android application permission metadata. Its classifications are intended to support privacy-oriented investigation and provide an initial indication of potentially sensitive permission usage.

There are several important limitations:

Declared permissions do not necessarily indicate that an application actively uses the associated functionality.

Permission declarations alone cannot establish what personal data an application actually collects, processes or transmits.

The categorisation process uses predefined mappings and heuristic rules; some permissions may require manual interpretation.

The tool does not perform dynamic application analysis, network traffic inspection or runtime behaviour monitoring.

The output should be treated as an investigative aid rather than a definitive privacy assessment or quantitative risk score.

Security and Responsible Use

Do not commit VirusTotal API keys or other credentials to the repository.

Use an environment variable or another secure configuration method for API credentials.

Check the provenance and redistribution rights of application hashes and associated sample data before publishing them.

Review generated reports before sharing them publicly, particularly if they contain sensitive or identifying information.

Project Focus

PRAFM explores the relationship between Android application permissions and mobile privacy. It brings together automated metadata collection, permission classification and privacy-oriented categorisation to support a more structured understanding of the information and device capabilities an application may request.

Areas of interest: Mobile Application Security · Android Privacy · Permission Analysis · Data Protection · Privacy Engineering

<div align="center">

Developed as a practical exploration of privacy assessment in Android applications.

</div>
