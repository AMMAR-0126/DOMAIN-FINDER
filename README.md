# ⬡ SENTINEL-X Security Suite v2.0

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Stars](https://img.shields.io/github/stars/AMMAR-0126/Vulnerability_Scanner?style=social)

> A portable, database-less vulnerability scanner with a sleek dark GUI — built for Kali Linux.
> Wraps **Nmap** and **Nikto** into one unified security suite.

---

## ✨ Features

- 🌐 **Network Scanner** — Powered by Nmap with 8 built-in scan profiles
- 🕷️ **Web Auditor** — Powered by Nikto for web vulnerability detection
- 🔓 **Open Port Detection** — Live port table with service & protocol info
- 🎯 **Severity Classification** — Auto-tags output as Critical / High / Warning / Info
- 💾 **JSON Report Manager** — Save, view, and delete scan reports
- ⏹️ **Stop Scan** — Abort any running scan instantly
- 🎨 **Dark Hacker UI** — Teal-green accent, monospace fonts, minimal design

---

## 🔍 Nmap Scan Profiles

| Profile | Flags | Use Case |
|---------|-------|----------|
| Quick Scan | `-T4 -F` | Fast top ports scan |
| Full Port Scan | `-T4 -p-` | All 65535 ports |
| Service & Version | `-T4 -sV -sC` | Detect service versions |
| OS Detection | `-T4 -O --osscan-guess` | Identify target OS |
| Stealth SYN | `-T2 -sS` | Low-noise SYN scan |
| UDP Scan | `-sU -T3 --top-ports 100` | Top UDP ports |
| Vuln Scripts | `-T4 --script vuln` | Run NSE vulnerability scripts |
| Aggressive | `-T4 -A` | Full aggressive scan |

---

## 🛠️ Requirements

**System Tools:**
```bash
sudo apt install nmap nikto python3-tk
```

**Python:** 3.x (standard library only — no pip install needed)

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/AMMAR-0126/Vulnerability_Scanner.git

# Navigate into the folder
cd Vulnerability_Scanner

# Run the tool
python3 sentinel_main.py
```

---

## 🚀 Usage

```bash
python3 sentinel_main.py
```

### Network Scan Tab
1. Enter target IP or hostname in the **TARGET** field (e.g. `192.168.1.1`)
2. Select a scan profile from the **PROFILE** dropdown
3. Click **▶ START SCAN**
4. View color-coded results in the output console
5. Detected open ports appear in the **OPEN PORTS** table
6. Click **💾 SAVE REPORT** to export results as JSON

### Web Audit Tab
1. Enter the target URL in the **TARGET URL** field (e.g. `http://192.168.1.1`)
2. Optionally add extra Nikto flags (default: `-Tuning 1234567`)
3. Click **▶ START AUDIT**
4. Color-coded Nikto output will stream in real time

### View Reports Tab
- Browse saved reports in the left panel
- Click any report to view summary cards and raw output
- Use **↻ REFRESH** to update the list
- Use **🗑 DELETE** to remove a report

---

## 📁 Project Structure

```
Vulnerability_Scanner/
├── sentinel_main.py    # Main application (single-file, all-in-one)
├── README.md           # Documentation
└── reports/            # Auto-created — JSON scan reports saved here
```

---

## 🎨 Severity Color Coding

| Color | Level | Triggered By |
|-------|-------|--------------|
| 🔴 Red | Critical | CVE, exploit, backdoor, vulnerable |
| 🟠 Amber | High | open, admin, login, password, auth |
| 🟡 Yellow | Warning | outdated, deprecated, notice |
| 🔵 Blue | Info | filtered, closed, info |
| ⚪ White | Normal | Everything else |

---

## ⚠️ Disclaimer

> This tool is intended for **educational purposes** and **authorized security testing only.**
> Do **NOT** use this tool against any system without **explicit written permission.**
> The developer is **not responsible** for any misuse or damage caused by this tool.
> Always comply with your local laws and ethical guidelines.

---

## 👨‍💻 Author

**AMMAR-0126**
- 🐙 GitHub: [@AMMAR-0126](https://github.com/AMMAR-0126)
- 🔗 Repo: [Vulnerability_Scanner](https://github.com/AMMAR-0126/Vulnerability_Scanner)

---

## 📄 License

This project is licensed under the **MIT License** — free to use, modify, and distribute.

---

<div align="center">
⭐ <b>If you found this useful, please give it a star!</b> ⭐
</div>
