<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
“Identified and contained unauthorized TOR traffic in simulated
enterprise environment, preventing potential exfiltration.”
- [Scenario Creation](https://github.com/MaryAnnaMoore07/Threat-Hunting-Scenario-Tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user “nack07" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-05-01T19:52:31.1014289Z`. These events began at `2025-05-01T19:39:06.1779878Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "maryanna-vm-mde"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "nack07"
| where Timestamp >= datetime(2025-05-01T19:39:06.1779878Z)
| order by Timestamp desc
| project Timestamp, ActionType, DeviceName, FileName, Account = InitiatingProcessAccountName, SHA256

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/da597823-12bd-4c6b-b858-9430d0408d0b">


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.1.exe". Based on the logs returned, at `2025-05-01T19:42:06.5826529Z`, a user by the name of nack07 on the "maryanna-vm-mde" device ran the file `tor-browser-windows-x86_64-portable-14.5.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "maryanna-vm-mde"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe"
| project Timestamp, DeviceName,  AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/c41d3f65-5e81-4217-900e-207e8a7d8a22">


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "nack07" opened the TOR browser. There was evidence that they did open it at `2025-05-01T19:42:37.2977226Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "maryanna-vm-mde"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName,  AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/e39cb6b6-46c2-4b5d-80dd-d495b3c9bafe">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication that the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-01T19:42:44.9277544Z`, a user by the name of "nack07" on the maryanna-vm-mde device successfully established a connection to the remote IP address `146.59.45.167` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "maryanna-vm-mde"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f7c50b38-5b22-43a2-8b42-20072ed60d91">


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-01T19:39:06.1779878Z`
- **Event:** The user "nack07" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\nack07\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-01T19:42:06.5826529Z`
- **Event:** The user "nack07" executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe /S`
- **File Path:** `C:\Users\nack07\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-01T19:42:37.2977226Z`
- **Event:** User "nack07" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\nack07\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-01T19:42:44.9277544Z`
- **Event:** A network connection to IP `146.59.45.167` on port `9001` by user "nack07" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\nack07\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-01T19:40:53.0212191Z` - Connected to `95.216.163.36` on port `443`.
  - `2025-05-01T19:42:44.9277544Z` - Local connection to `127.0.0.1` on port `9151`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "nack07" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-01T19:52:31.1014289Z`
- **Event:** The user "nack07" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\nack07\Desktop\tor-shopping-list.txt`

---

## Summary

The user "nack07" on the "maryanna-vm-mde" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and create various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `maryanna-vm-mde` by the user `nack07`. The device was isolated, and the user's direct manager was notified.

---
