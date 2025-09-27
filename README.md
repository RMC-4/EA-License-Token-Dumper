# 🛠️ EA Denuvo Token Dumper

A lightweight **Windows GUI tool** written in PowerShell that extracts the **Denuvo Token** from EA license files (`*.dlf`) and optionally updates an `anadius.cfg` file.  

This project is fully **open source** to reduce false positives and build trust — you can inspect the PowerShell code and build the executable yourself.

---

## ✨ Features
- 🔑 Extracts **Denuvo Token** from EA license files  
- 📝 Optionally **backs up & updates** an `anadius.cfg` file  
- 💾 Creates an automatic `.bak` backup before modifying configs  
- 🖥️ Clean and simple **Windows Forms GUI**  
- 📋 Displays the extracted token in the app for easy copy-paste  

---

## 📥 Download
Grab the latest release here 👉 [Releases](../../releases)

You’ll find:
- `EA Denuvo Token Dumper.exe` – prebuilt Windows binary  
- `token_dumper.ps1` – PowerShell source code  

Each release includes a **SHA256 hash** so you can verify integrity.

---

## 🚀 Usage
1. Launch the tool:  
   - Run **`EA Denuvo Token Dumper.exe`**, or  
   - Open **`token_dumper.ps1`** with PowerShell  

2. Select your **license file** (`*.dlf`).  
   - Default location:  C:\ProgramData\Electronic Arts\EA Services\License\16425677_sc.dlf

3. (Optional) Select your **config file** (`anadius.cfg`).  
   - ✅ “Add DenuvoToken to anadius.cfg even if it exists”  
   - If checked → token will be written into `anadius.cfg`  
   - If unchecked → token is only shown in the app  

4. Click **Start** to extract the token.  

---

## 🔨 Build Instructions
Want to build your own executable? Easy:

1. Install [ps2exe](https://www.powershellgallery.com/packages/ps2exe):
   ```powershell
   Install-Module -Name ps2exe -Scope CurrentUser -Force

2. Build: build.bat or 
Invoke-ps2exe .\token_dumper.ps1 ".\EA Denuvo Token Dumper.exe" -noConsole

3. The resulting EA Denuvo Token Dumper.exe will be in your folder.


---

## 🛡️ Security & False Positives
This project is not malware.
Antivirus tools sometimes flag self-built PowerShell → EXE files due to heuristics.

✅ Source code is public and auditable
✅ SHA256 hashes provided for every release
✅ You can rebuild the binary yourself from source

If you encounter false positives, please open an issue

---

## 🙏 Credits
Developed by RMC
Thanks to Sodium and anadius for their contributions and references

---
