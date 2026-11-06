# ─────────────────────────────────────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────────────────────────────────────
import requests
import csv
import re
import xml.etree.ElementTree as ET
import json
import os
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────────────────────────────────────
# Configuration Constants
# ─────────────────────────────────────────────────────────────────────────────
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# List of file hashes to process
HASHES = [...]

# Filenames for output
CSV_FILENAME = "permissions_report.csv"
UNCERTAIN_LOG = "uncertain_permissions_log.txt"

# ─────────────────────────────────────────────────────────────────────────────
# Known Permission Definitions
# ─────────────────────────────────────────────────────────────────────────────
# Permissions that are visible to the user

USER_VISIBLE_PERMISSIONS = [
    "ANDROID.PERMISSION.ACCESS_BACKGROUND_LOCATION",
    "ANDROID.PERMISSION.ACCESS_COARSE_LOCATION",
    "ANDROID.PERMISSION.ACCESS_DOWNLOAD_MANAGER",
    "ANDROID.PERMISSION.ACCESS_DOWNLOAD_MANAGER_ADVANCED",
    "ANDROID.PERMISSION.ACCESS_FINE_LOCATION",
    "ANDROID.PERMISSION.ACCESS_INSTANT_APPS",
    "ANDROID.PERMISSION.ACCESS_NETWORK_STATE",
    "ANDROID.PERMISSION.ACCESS_NOTIFICATION_POLICY",
    "ANDROID.PERMISSION.ACCESS_WIFI_STATE",
    "ANDROID.PERMISSION.BLUETOOTH",
    "ANDROID.PERMISSION.BLUETOOTH_CONNECT",
    "ANDROID.PERMISSION.BODY_SENSORS",
    "ANDROID.PERMISSION.CALL_PHONE",
    "ANDROID.PERMISSION.CAMERA",
    "ANDROID.PERMISSION.CHANGE_NETWORK_STATE",
    "ANDROID.PERMISSION.CHANGE_WIFI_STATE",
    "ANDROID.PERMISSION.DELETE_PACKAGES",
    "ANDROID.PERMISSION.FORCE_STOP_PACKAGES",
    "ANDROID.PERMISSION.FOREGROUND_SERVICE",
    "ANDROID.PERMISSION.GET_ACCOUNTS",
    "ANDROID.PERMISSION.INSTALL_PACKAGES",
    "ANDROID.PERMISSION.INTERNET",
    "ANDROID.PERMISSION.MANAGE_MEDIA",
    "ANDROID.PERMISSION.MANAGE_OWN_CALLS",
    "ANDROID.PERMISSION.POST_NOTIFICATIONS",
    "ANDROID.PERMISSION.READ_CALENDAR",
    "ANDROID.PERMISSION.READ_CALL_LOG",
    "ANDROID.PERMISSION.READ_CONTACTS",
    "ANDROID.PERMISSION.READ_EXTERNAL_STORAGE",
    "ANDROID.PERMISSION.READ_PHONE_NUMBERS",
    "ANDROID.PERMISSION.READ_PHONE_STATE",
    "ANDROID.PERMISSION.READ_PRIVILEGED_PHONE_STATE",
    "ANDROID.PERMISSION.READ_SMS",
    "ANDROID.PERMISSION.RECEIVE_MMS",
    "ANDROID.PERMISSION.RECEIVE_SMS",
    "ANDROID.PERMISSION.RECORD_AUDIO",
    "ANDROID.PERMISSION.REVOKE_RUNTIME_PERMISSIONS",
    "ANDROID.PERMISSION.SCHEDULE_EXACT_ALARM",
    "ANDROID.PERMISSION.SEND_DOWNLOAD_COMPLETED_INTENTS",
    "ANDROID.PERMISSION.SEND_SMS",
    "ANDROID.PERMISSION.USE_BIOMETRIC",
    "ANDROID.PERMISSION.USE_FINGERPRINT",
    "ANDROID.PERMISSION.VIBRATE",
    "ANDROID.PERMISSION.WRITE_CALENDAR",
    "ANDROID.PERMISSION.WRITE_CALL_LOG",
    "ANDROID.PERMISSION.WRITE_CONTACTS",
    "ANDROID.PERMISSION.WRITE_EXTERNAL_STORAGE",
    "ANDROID.PERMISSION.WRITE_SMS",
    "COM.GOOGLE.ANDROID.GM.PERMISSION.AUTO_SEND"
]

# Permissions that are hidden to the user
USER_HIDDEN_PERMISSIONS = [
    "ANDROID.PERMISSION.ACTIVITY_RECOGNITION",
    "ANDROID.PERMISSION.ALLOCATE_AGGRESSIVE",
    "ANDROID.PERMISSION.AUTHENTICATE_ACCOUNTS",
    "ANDROID.PERMISSION.BACKUP",
    "ANDROID.PERMISSION.BATTERY_STATS",
    "ANDROID.PERMISSION.BIND_WALLPAPER",
    "ANDROID.PERMISSION.BROADCAST_STICKY",
    "ANDROID.PERMISSION.CHANGE_COMPONENT_ENABLED_STATE",
    "ANDROID.PERMISSION.CHANGE_DEVICE_IDLE_TEMP_WHITELIST",
    "ANDROID.PERMISSION.CHANGE_OVERLAY_PACKAGES",
    "ANDROID.PERMISSION.CLEAR_APP_CACHE",
    "ANDROID.PERMISSION.CONNECTIVITY_INTERNAL",
    "ANDROID.PERMISSION.DISABLE_KEYGUARD",
    "ANDROID.PERMISSION.DOWNLOAD_WITHOUT_NOTIFICATION",
    "ANDROID.PERMISSION.DUMP",
    "ANDROID.PERMISSION.GET_ACCOUNTS_PRIVILEGED",
    "ANDROID.PERMISSION.GET_APP_OPS_STATS",
    "ANDROID.PERMISSION.GET_PACKAGE_SIZE",
    "ANDROID.PERMISSION.GET_TASKS",
    "ANDROID.PERMISSION.GRANT_RUNTIME_PERMISSIONS",
    "ANDROID.PERMISSION.HIDE_NON_SYSTEM_OVERLAY_WINDOWS",
    "ANDROID.PERMISSION.HIDE_OVERLAY_WINDOWS",
    "ANDROID.PERMISSION.INSTALL_GRANT_RUNTIME_PERMISSIONS",
    "ANDROID.PERMISSION.INTERACT_ACROSS_PROFILES",
    "ANDROID.PERMISSION.INTERACT_ACROSS_USERS",
    "ANDROID.PERMISSION.LAUNCH_TWO_PANE_SETTINGS_DEEP_LINK",
    "ANDROID.PERMISSION.LOADER_USAGE_STATS",
    "ANDROID.PERMISSION.MANAGE_ACCOUNTS",
    "ANDROID.PERMISSION.MANAGE_APP_OPS_MODES",
    "ANDROID.PERMISSION.MANAGE_ROLLBACKS",
    "ANDROID.PERMISSION.MANAGE_USERS",
    "ANDROID.PERMISSION.MODIFY_AUDIO_SETTINGS",
    "ANDROID.PERMISSION.NFC",
    "ANDROID.PERMISSION.OVERRIDE_COMPAT_CHANGE_CONFIG_ON_RELEASE_BUILD",
    "ANDROID.PERMISSION.PACKAGE_USAGE_STATS",
    "ANDROID.PERMISSION.PACKAGE_VERIFICATION_AGENT",
    "ANDROID.PERMISSION.QUERY_ALL_PACKAGES",
    "ANDROID.PERMISSION.READ_APP_BADGE",
    "ANDROID.PERMISSION.READ_PHONE_NUMBERS",
    "ANDROID.PERMISSION.REAL_GET_TASKS",
    "ANDROID.PERMISSION.REBOOT",
    "ANDROID.PERMISSION.RECEIVE_BOOT COMPLETED",
    "ANDROID.PERMISSION.RECEIVE_BOOT_COMPLETED",
    "ANDROID.PERMISSION.SEND_DEVICE_CUSTOMIZATION_READY",
    "ANDROID.PERMISSION.SET_DEFAULT_ACCOUNT_FOR_CONTACTS",
    "ANDROID.PERMISSION.SET_HARMFUL_APP_WARNINGS",
    "ANDROID.PERMISSION.SET_PREFERRED_APPLICATIONS",
    "ANDROID.PERMISSION.SET_WALLPAPER",
    "ANDROID.PERMISSION.START_ACTIVITIES_FROM_BACKGROUND",
    "ANDROID.PERMISSION.START_FOREGROUND_SERVICES_FROM_BACKGROUND",
    "ANDROID.PERMISSION.STATUS_BAR",
    "ANDROID.PERMISSION.SUBSCRIBED_FEEDS_READ",
    "ANDROID.PERMISSION.SUBSCRIBED_FEEDS_WRITE",
    "ANDROID.PERMISSION.SUBSTITUTE_NOTIFICATION_APP_NAME",
    "ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW",
    "ANDROID.PERMISSION.UPDATE_DEVICE_STATS",
    "ANDROID.PERMISSION.USE_CREDENTIALS",
    "ANDROID.PERMISSION.USE_FULL_SCREEN_INTENT",
    "ANDROID.PERMISSION.WAKE_LOCK",
    "ANDROID.PERMISSION.WRITE_SECURE_SETTINGS",
    "ANDROID.PERMISSION.WRITE_SETTINGS",
    "ANDROID.PERMISSION.WRITE_SYNC_SETTINGS",
    "COM.ANDDOES.LAUNCHER.PERMISSION.UPDATE_COUNT",
    "COM.ANDROID.CHROME.PERMISSION.SHOW_COMPLIANCE_SCREEN",
    "COM.ANDROID.EMAIL.PARTNERPROVIDER.PARTNER_PROVIDER",
    "COM.ANDROID.LAUNCHER.PERMISSION.INSTALL_SHORTCUT",
    "COM.ANDROID.PERMISSION.USE_INSTALLER_V2",
    "COM.ANDROID.SYSTEMUI.PERMISSION.SEND_ALERT_BROADCASTS",
    "COM.ANDROID.VENDING.BILLING.IN_APP_NOTIFY.PERMISSION.C2D_MESSAGE",
    "COM.ANDROID.VENDING.INTENT_VENDING_ONLY",
    "COM.ANDROID.VENDING.PERMISSION.C2D_MESSAGE",
    "COM.ANDROID.VENDING.TOS_ACKED",
    "COM.GOOGLE.ANDROID.APPS.MAPS.PERMISSION.PREFETCH",
    "COM.GOOGLE.ANDROID.C2DM.PERMISSION.RECEIVE",
    "COM.GOOGLE.ANDROID.CALENDAR.PERMISSION.C2D_MESSAGE",
    "COM.GOOGLE.ANDROID.CALENDAR.PERMISSION.READ_OOBE",
    "COM.GOOGLE.ANDROID.ELMYRA.PERMISSION.CONFIGURE_ASSIST_GESTURE",
    "COM.GOOGLE.ANDROID.EMAIL.PERMISSION.ACCESS_PROVIDER",
    "COM.GOOGLE.ANDROID.EMAIL.PERMISSION.READ_ATTACHMENT",
    "COM.GOOGLE.ANDROID.FINSKY.PERMISSION.DEVELOPER_GROUP_ID_INFO",
    "COM.GOOGLE.ANDROID.FINSKY.PERMISSION.INSTANT_APP_STATE",
    "COM.GOOGLE.ANDROID.FINSKY.PERMISSION.INTERNAL_BROADCAST",
    "COM.GOOGLE.ANDROID.GM.EMAIL.PERMISSION.ACCESS_PROVIDER",
    "COM.GOOGLE.ANDROID.GM.EMAIL.PERMISSION.GET_WIDGET_UPDATE",
    "COM.GOOGLE.ANDROID.GM.EMAIL.PERMISSION.READ_ATTACHMENT",
    "COM.GOOGLE.ANDROID.GM.EXCHANGE.BIND",
    "COM.GOOGLE.ANDROID.GM.PERMISSION.BROADCAST_INTERNAL",
    "COM.GOOGLE.ANDROID.GM.PERMISSION.READ_GMAIL",
    "COM.GOOGLE.ANDROID.GM.PERMISSION.WRITE_GMAIL",
    "COM.GOOGLE.ANDROID.GMS.AUTH.PERMISSION.GOOGLE_ACCOUNT_CHANGE",
    "COM.GOOGLE.ANDROID.GMS.PERMISSION.ACTIVITY_RECOGNITION",
    "COM.GOOGLE.ANDROID.GMS.PERMISSION.AD_ID_NOTIFICATION",
    "COM.GOOGLE.ANDROID.GMS.PERMISSION.CAR",
    "COM.GOOGLE.ANDROID.GMS.PERMISSION.CAR_SPEED",
    "COM.GOOGLE.ANDROID.GMS.PERMISSION.REQUEST_SCREEN_LOCK_COMPLEXITY",
    "COM.GOOGLE.ANDROID.GMS.WRITE_VERIFY_APPS_CONSENT",
    "COM.GOOGLE.ANDROID.GOOGLEAPPS.PERMISSION.GOOGLE_AUTH",
    "COM.GOOGLE.ANDROID.GOOGLEAPPS.PERMISSION.GOOGLE_AUTH.MAIL",
    "COM.GOOGLE.ANDROID.GOOGLEQUICKSEARCHBOX.PERMISSION.LAUNCH_FROM_GMM",
    "COM.GOOGLE.ANDROID.GOOGLEQUICKSEARCHBOX.PERMISSION.LENSVIEW_BROADCAST",
    "COM.GOOGLE.ANDROID.HANGOUTS.START_HANGOUT",
    "COM.GOOGLE.ANDROID.PARTNERSETUP.PERMISSION.WRITE_APP_PROVIDER",
    "COM.GOOGLE.ANDROID.PROVIDERS.GSF.PERMISSION.READ_GSERVICES",
    "COM.GOOGLE.ANDROID.PROVIDERS.GSF.PERMISSION.WRITE_GSERVICES",
    "COM.GOOGLE.ANDROID.SETUPWIZARD.SETUP_PROGRESS_SERVICE",
    "COM.GOOGLE.ANDROID.TALK.PERMISSION.C2D_MESSAGE",
    "COM.GOOGLE.ANDROID.VOICESEARCH.AUDIO_FILE_ACCESS",
    "COM.HTC.LAUNCHER.PERMISSION.READ_SETTINGS",
    "COM.HTC.LAUNCHER.PERMISSION.UPDATE_SHORTCUT",
    "COM.HUAWEI.ANDROID.LAUNCHER.PERMISSION.CHANGE_BADGE",
    "COM.HUAWEI.ANDROID.LAUNCHER.PERMISSION.READ_SETTINGS",
    "COM.HUAWEI.ANDROID.LAUNCHER.PERMISSION.WRITE_SETTINGS",
    "COM.MAJEUR.LAUNCHER.PERMISSION.UPDATE_BADGE",
    "COM.OPPO.LAUNCHER.PERMISSION.READ_SETTINGS",
    "COM.OPPO.LAUNCHER.PERMISSION.WRITE_SETTINGS",
    "COM.SEC.ANDROID.PROVIDER.BADGE.PERMISSION.READ",
    "COM.SEC.ANDROID.PROVIDER.BADGE.PERMISSION.WRITE",
    "COM.SONYERICSSON.HOME.PERMISSION.BROADCAST_BADGE",
    "COM.SONYMOBILE.HOME.PERMISSION.PROVIDER_INSERT_BADGE",
    "ORG.CHROMIUM.ARC.APKCACHEPROVIDER.PERMISSION.READ_CACHE",
    "ORG.CHROMIUM.ARC.APKCACHEPROVIDER.PERMISSION.WRITE_CACHE"
]

# ─────────────────────────────────────────────────────────────────────────────
# Permission Category Mappings
# ─────────────────────────────────────────────────────────────────────────────
# Explicit mapping of permissions to categories

PERMISSION_CATEGORIES = {
    "ANDROID.PERMISSION.ACCESS_BACKGROUND_LOCATION": "PII",
    "ANDROID.PERMISSION.ACCESS_COARSE_LOCATION": "PII",
    "ANDROID.PERMISSION.ACCESS_DOWNLOAD_MANAGER": "Digital",
    "ANDROID.PERMISSION.ACCESS_DOWNLOAD_MANAGER_ADVANCED": "Digital",
    "ANDROID.PERMISSION.ACCESS_FINE_LOCATION": "PII",
    "ANDROID.PERMISSION.ACCESS_INSTANT_APPS": "Digital",
    "ANDROID.PERMISSION.ACCESS_NETWORK_STATE": "Digital",
    "ANDROID.PERMISSION.ACCESS_NOTIFICATION_POLICY": "Digital",
    "ANDROID.PERMISSION.ACCESS_WIFI_STATE": "Digital",
    "ANDROID.PERMISSION.ACTIVITY_RECOGNITION": "Cyberphysical",
    "ANDROID.PERMISSION.ALLOCATE_AGGRESSIVE": "Cyberphysical",
    "ANDROID.PERMISSION.AUTHENTICATE_ACCOUNTS": "PII",
    "ANDROID.PERMISSION.BACKUP": "PII",
    "ANDROID.PERMISSION.BATTERY_STATS": "Cyberphysical",
    "ANDROID.PERMISSION.BIND_WALLPAPER": "PII",
    "ANDROID.PERMISSION.BLUETOOTH": "Cyberphysical",
    "ANDROID.PERMISSION.BLUETOOTH_CONNECT": "Cyberphysical",
    "ANDROID.PERMISSION.BROADCAST_STICKY": "Digital",
    "ANDROID.PERMISSION.CALL_PHONE": "PII",
    "ANDROID.PERMISSION.CAMERA": "PII",
    "ANDROID.PERMISSION.CHANGE_NETWORK_STATE": "Digital",
    "ANDROID.PERMISSION.CHANGE_WIFI_STATE": "Digital",
    "ANDROID.PERMISSION.DELETE_PACKAGES": "Digital",
    "ANDROID.PERMISSION.FORCE_STOP_PACKAGES": "Digital",
    "ANDROID.PERMISSION.FOREGROUND_SERVICE": "Digital",
    "ANDROID.PERMISSION.GET_ACCOUNTS": "PII",
    "ANDROID.PERMISSION.INSTALL_PACKAGES": "Digital",
    "ANDROID.PERMISSION.INTERNET": "Digital",
    "ANDROID.PERMISSION.MANAGE_MEDIA": "PII",
    "ANDROID.PERMISSION.MANAGE_OWN_CALLS": "PII",
    "ANDROID.PERMISSION.POST_NOTIFICATIONS": "Digital",
    "ANDROID.PERMISSION.READ_CALENDAR": "PII",
    "ANDROID.PERMISSION.READ_CALL_LOG": "Unknown",
    "ANDROID.PERMISSION.READ_CONTACTS": "PII",
    "ANDROID.PERMISSION.READ_EXTERNAL_STORAGE": "PII",
    "ANDROID.PERMISSION.READ_PHONE_NUMBERS": "PII",
    "ANDROID.PERMISSION.READ_PHONE_STATE": "PII",
    "ANDROID.PERMISSION.READ_PRIVILEGED_PHONE_STATE": "PII",
    "ANDROID.PERMISSION.READ_SMS": "PII",
    "ANDROID.PERMISSION.RECEIVE_MMS": "PII",
    "ANDROID.PERMISSION.RECEIVE_SMS": "PII",
    "ANDROID.PERMISSION.RECORD_AUDIO": "Cyberphysical",
    "ANDROID.PERMISSION.REVOKE_RUNTIME_PERMISSIONS": "Digital",
    "ANDROID.PERMISSION.SCHEDULE_EXACT_ALARM": "Cyberphysical",
    "ANDROID.PERMISSION.SEND_DOWNLOAD_COMPLETED_INTENTS": "Digital",
    "ANDROID.PERMISSION.SEND_SMS": "PII",
    "ANDROID.PERMISSION.USE_BIOMETRIC": "PII",
    "ANDROID.PERMISSION.USE_FINGERPRINT": "PII",
    "ANDROID.PERMISSION.VIBRATE": "Cyberphysical",
    "ANDROID.PERMISSION.WRITE_CALENDAR": "PII",
    "ANDROID.PERMISSION.WRITE_CALL_LOG": "Unknown",
    "ANDROID.PERMISSION.WRITE_CONTACTS": "Digital",
    "ANDROID.PERMISSION.WRITE_EXTERNAL_STORAGE": "PII",
    "ANDROID.PERMISSION.WRITE_SMS": "PII",
}

# Mapping from Android permission-groups to categories
GROUP_TO_CATEGORY = {
    "ANDROID.PERMISSION-GROUP.CALENDAR":       "PII",
    "ANDROID.PERMISSION-GROUP.CALL_LOG":       "PII",
    "ANDROID.PERMISSION-GROUP.CAMERA":         "Cyberphysical",
    "ANDROID.PERMISSION-GROUP.CONTACTS":       "PII",
    "ANDROID.PERMISSION-GROUP.LOCATION":       "PII",
    "ANDROID.PERMISSION-GROUP.MICROPHONE":     "Cyberphysical",
    "ANDROID.PERMISSION-GROUP.PHONE":          "PII",
    "ANDROID.PERMISSION-GROUP.SENSORS":        "Cyberphysical",
    "ANDROID.PERMISSION-GROUP.SMS":            "PII",
    "ANDROID.PERMISSION-GROUP.STORAGE":        "Digital",
    "ANDROID.PERMISSION-GROUP.NOTIFICATIONS":  "Digital",
    "ANDROID.PERMISSION-GROUP.NEARBY_DEVICES": "Cyberphysical",
    "ANDROID.PERMISSION-GROUP.NETWORK":        "Digital",
}

# ─────────────────────────────────────────────────────────────────────────────
# Heuristic Keyword Lists
# ─────────────────────────────────────────────────────────────────────────────
# Keywords for inferring PII-related permissions

PII_KEYWORDS = [
    "contact", "contacts", "call", "phone", "sms", "mms",
    "calendar", "account", "accounts", "profile", "sync", "email"
]

# Keywords for inferring cyberphysical permissions
CYBERPHYSICAL_KEYWORDS = [
    "camera", "record", "audio", "microphone", "sensor",
    "bluetooth", "vibrate", "gps", "location", "nfc",
    "wake_lock", "screen", "launcher", "speaker"
]

# Keywords for inferring digital permissions
DIGITAL_KEYWORDS = [
    "internet", "network", "storage", "download", "package",
    "install", "setting", "settings", "notification", "alarm",
    "foreground_service", "manager", "provider", "service",
    "broadcast", "data", "app"
]


# ─────────────────────────────────────────────────────────────────────────────
# Data Containers for AOSP Mappings
# ─────────────────────────────────────────────────────────────────────────────
# Populated at runtime via fetch_aosp_mappings()

PERM_TO_GROUP       = {}
PERM_TO_DESCRIPTION = {}

# ─────────────────────────────────────────────────────────────────────────────
# AOSP Mapping Fetch Functions
# ─────────────────────────────────────────────────────────────────────────────

def fetch_aosp_mappings():
    """
    Download & parse the AOSP AndroidManifest.xml to build:
      - PERM_TO_GROUP: permission → permissionGroup
      - PERM_TO_DESCRIPTION: permission → description
    """
    url = (
        "https://raw.githubusercontent.com/"
        "aosp-mirror/platform_frameworks_base/master/core/res/AndroidManifest.xml"
    )
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    for perm in root.findall(".//permission"):
        name  = perm.attrib.get("{http://schemas.android.com/apk/res/android}name")
        group = perm.attrib.get("{http://schemas.android.com/apk/res/android}permissionGroup")
        descr = perm.attrib.get("{http://schemas.android.com/apk/res/android}description")
        if name:
            key = name.upper()
            PERM_TO_GROUP[key] = (group or "").upper()
            if descr:
                PERM_TO_DESCRIPTION[key] = descr

# ─────────────────────────────────────────────────────────────────────────────
# Permission Description Fetch Functions
# ─────────────────────────────────────────────────────────────────────────────

def fetch_permission_jsonld(permission):
    """
    Fetch the JSON‑LD block from the permission's docs page
    for the official description.
    """
    suffix = permission.split('.')[-1]
    url    = f"https://developer.android.com/reference/android/Manifest.permission.{suffix}"
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
    except requests.RequestException:
        return None
    soup = BeautifulSoup(r.text, "html.parser")
    script = soup.find("script", {"type": "application/ld+json"})
    if not script or not script.string:
        return None
    try:
        data = json.loads(script.string)
        return data.get("description")
    except json.JSONDecodeError:
        return None

def fetch_permission_html_desc(permission):
    """
    Scrape the permission's individual doc page
    and return its main human‑readable description.
    """
    suffix = permission.split('.')[-1]
    url    = f"https://developer.android.com/reference/android/Manifest.permission.{suffix}"
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
    except requests.RequestException:
        return None

    soup = BeautifulSoup(r.text, "html.parser")
    jd = soup.select_one("div.jd-descr")
    if jd:
        text = jd.get_text(" ", strip=True)
        if text:
            return text
    main = soup.select_one("div.devsite-article-body")
    if main:
        p = main.find("p")
        if p:
            text = p.get_text(" ", strip=True)
            if text:
                return text
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Category Inference and Helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_web_metadata_for_category(permission):
    """
    Last‑resort category inference by scraping page text for keywords.
    """
    suffix = permission.split('.')[-1].lower()
    url    = f"https://developer.android.com/reference/android/Manifest.permission.{suffix}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code != 200:
            return "Unknown"
        text = BeautifulSoup(r.content, "html.parser")\
               .get_text(" ", strip=True).lower()
        if any(k in text for k in ("contact","phone")):
            return "PII"
        if any(k in text for k in ("location","gps")):
            return "PII"
        if any(k in text for k in ("camera","photo","video")):
            return "Cyberphysical"
        if any(k in text for k in ("record","audio","microphone")):
            return "Cyberphysical"
        if any(k in text for k in ("storage","network","internet","download")):
            return "Digital"
    except Exception:
        pass
    return "Unknown"

def get_permission_group(permission):
    return PERM_TO_GROUP.get(permission.strip().upper())

def get_visibility(permission, protection_level, pkg, logf):
    p = permission.strip().upper()
    if p in USER_VISIBLE_PERMISSIONS:
        return 1
    if p in USER_HIDDEN_PERMISSIONS:
        return 2
    if protection_level.lower() == "dangerous":
        return 1
    for pre in ("READ_","WRITE_","ACCESS_","RECORD_","SEND_","RECEIVE_","USE_","GET_"):
        if p.startswith(pre) and not any(x in p for x in ("SIGNATURE","INTERNAL","DEBUG")):
            return 1
    logf.write(f"[{pkg}] {p} (protection: {protection_level})\n")
    return 2

def categorize_permission(permission):
    pu = permission.strip().upper()
    if pu in PERMISSION_CATEGORIES:
        return PERMISSION_CATEGORIES[pu]
    grp = get_permission_group(pu)
    if grp in GROUP_TO_CATEGORY:
        return GROUP_TO_CATEGORY[grp]
    cat = get_web_metadata_for_category(pu)
    if cat != "Unknown":
        PERMISSION_CATEGORIES[pu] = cat
        return cat
    low = pu.lower()
    if   any(k in low for k in PII_KEYWORDS):           return "PII"
    elif any(k in low for k in CYBERPHYSICAL_KEYWORDS): return "Cyberphysical"
    elif any(k in low for k in DIGITAL_KEYWORDS):       return "Digital"
    return "Unknown"

def get_description(permission, short_desc, full_desc):
    pu = permission.strip().upper()
    if full_desc:
        return re.sub(r'\s+', ' ', full_desc.strip())
    if short_desc:
        return re.sub(r'\s+', ' ', short_desc.strip())
    if pu in PERM_TO_DESCRIPTION:
        return PERM_TO_DESCRIPTION[pu]
    jsonld = fetch_permission_jsonld(pu)
    if jsonld:
        return jsonld
    html_desc = fetch_permission_html_desc(pu)
    if html_desc:
        return html_desc
    return ""

# ─────────────────────────────────────────────────────────────────────────────
# Permission Collection Logic
# ─────────────────────────────────────────────────────────────────────────────

def collect_permissions(data, pkg, logf):
    """
    Walk VT JSON and return a list of permission rows (excluding total).
    Each row is [pkg, permission, protection, description, visibility, category]
    """
    rows = []
    def recurse(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if isinstance(val, dict) and 'permission_type' in val:
                    prot = val.get('permission_type', 'N/A')
                    desc = get_description(key, val.get('short_description', ''), val.get('full_description', ''))
                    vis  = get_visibility(key, prot, pkg, logf)
                    cat  = categorize_permission(key)
                    rows.append([pkg, key, prot, desc, vis, cat])
                elif isinstance(val, (dict, list)):
                    recurse(val)
        elif isinstance(obj, list):
            for item in obj:
                recurse(item)
    recurse(data)
    return rows

# ─────────────────────────────────────────────────────────────────────────────
# Main Execution Flow
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("Fetching AOSP mappings…")
    fetch_aosp_mappings()
    print(f"Loaded {len(PERM_TO_GROUP)} permissions from AOSP.")

    with open(CSV_FILENAME, "w", newline="", encoding="utf-8") as csvf, \
         open(UNCERTAIN_LOG, "w", encoding="utf-8") as logf:

        writer = csv.writer(csvf)
        # Header row with total-permissions first
        writer.writerow([
            "Total Permissions",
            "Package",
            "Permission",
            "Protection Level",
            "Description",
            "User Visibility",
            "Category"
        ])

        for h in HASHES:
            print(f"\n→ Fetching hash: {h}")
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{h}",
                headers={"x-apikey": API_KEY},
                timeout=10
            )
            if r.status_code != 200:
                print(f"Error fetching {h}: {r.status_code}")
                continue

            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            names = attrs.get("names") or []
            pkg = names[0] if names else data.get("id", "Unknown Package")

            # Collect all rows for this package
            rows = collect_permissions(attrs, pkg, logf)
            total = len(rows)

            # Write each row, prefixed with total count
            for row in rows:
                writer.writerow([total] + row)

    print(f"\n Report saved to {CSV_FILENAME}")
    print(f" Uncertain log: {UNCERTAIN_LOG}")

# Entry point
if __name__ == "__main__":
    main()
