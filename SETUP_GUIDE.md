# Setup Guide: Deploying on a Fresh Machine

This guide explains how to set up and run the Enhanced Network Traffic Analyzer on a new computer (Linux, Windows, or macOS) from scratch.

## 1. Prerequisites (Before you start)

### Operating System
*   **Linux**: Recommended (Kali, Ubuntu, Debian, CentOS).
*   **Windows**: 10 or 11.
*   **macOS**: Supported (Intel or Apple Silicon).

### Required Software
1.  **Java Runtime (JRE)**: Version 8 or higher.
2.  **Packet Capture Driver**:
    *   **Linux**: `libpcap` (Usually installed by default, or `libpcap-dev`).
    *   **Windows**: `Npcap` (Must be installed separately).
    *   **macOS**: `libpcap` (Pre-installed).

---

## 2. Installation Steps

### Step 1: Install Dependencies

#### On Linux (Ubuntu/Kali/Debian)
Open your terminal and run:
```bash
sudo apt update
sudo apt install openjdk-17-jre-headless libpcap0.8
```

#### On Windows
1.  **Install Java**: Download **OpenJDK 17** from [Adoptium.net](https://adoptium.net/) and run the installer.
2.  **Install Npcap**:
    *   Download from [Npcap.com](https://npcap.com/).
    *   Run installer. **IMPORTANT**: Check the box **"Install Npcap in WinPcap API-compatible Mode"**.

### Step 2: Get the Application
You do **not** need to compile the code on the new machine. You only need the **JAR file**.

1.  On your source machine, locate: `net-traffic-analysis-1.0-SNAPSHOT.jar` (in the `target/` folder).
2.  Copy this file to the new machine (e.g., via USB, SCP, or Email).
3.  Place it in a folder, for example: `C:\TrafficTool\` (Windows) or `~/traffic-tool/` (Linux).

---

## 3. How to Run

### Linux / macOS
1.  Open Terminal.
2.  Navigate to the folder:
    ```bash
    cd ~/traffic-tool/
    ```
3.  Identify your network interface name:
    ```bash
    ip addr   # Look for names like eth0, wlan0, ens33
    ```
4.  Run the tool (Requires Root/Sudo):
    ```bash
    sudo java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i eth0 -o live_data.csv
    ```

### Windows
1.  Open **Command Prompt** or **PowerShell** as **Administrator**. (Right-click -> Run as Administrator).
2.  Navigate to the folder:
    ```cmd
    cd C:\TrafficTool\
    ```
3.  Identify interface index/name (The tool will list them if you provide a wrong one, or check `ipconfig`).
4.  Run:
    ```cmd
    java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i 0 -o live_data.csv
    ```
    *(Note: On Windows, sometimes you use the index number `0`, `1`, etc., if the name is complex. The tool lists available NIFs if you just run `java -jar ...` without arguments).*

---

## 4. Verification Check
To ensure it is working on the new machine:
1.  Run the command.
2.  You should see:
    ```text
    [main] INFO ... Pcap4J successfully loaded a native pcap library...
    Listening on interface: eth0
    ```
3.  Generate some traffic (open a browser).
4.  Press `Ctrl+C`.
5.  Open `live_data.csv` and check if rows are populated.

---

## 5. Troubleshooting Common Issues

| Error Message | Cause | Solution |
| :--- | :--- | :--- |
| `'java' is not recognized` | Java is not installed or not in PATH | Install OpenJDK and ensure "Add to PATH" is selected. |
| `PcapNativeException` / `UnsatisfiedLinkError` | Missing capture driver | **Linux**: `sudo apt install libpcap0.8`.<br>**Windows**: Install **Npcap** in WinPcap-compatible mode. |
| `Permission denied` / `Operation not permitted` | User is not Admin/Root | **Linux**: Add `sudo`.<br>**Windows**: Run CMD as Administrator. |
| `Interface not found` | Typo in interface name | Run the tool without `-i` allows you to inspect code or create a list loop to print available interfaces. |
