<p align="center">
  <img src="assets/banner.png" alt="Offensive AI Banner">
</p>

<p align="center">
  <img src="assets/logo.png" width="140" alt="Offensive AI Logo">
</p>

<h1 align="center">🛡️ Offensive AI – Attack Path Visualizer</h1>

<p align="center">
AI-powered offensive security framework that transforms raw recon data into realistic, prioritised attack paths using local AI reasoning.
</p>

<p align="center">
⚠️ <strong>For legal & authorised security testing and educational purposes only.</strong>
</p>

---

## 🚀 What is Offensive AI?

**Offensive AI – Attack Path Visualizer** is a Windows-first offensive security framework designed to help security professionals **think like a real attacker**, not just collect tool outputs.

Instead of showing scattered scan results, this framework:
- Correlates recon & scan signals  
- Applies AI-driven reasoning using a **local LLM (llama.cpp)**  
- Generates **realistic attack paths**  
- Presents everything in a clean, analyst-friendly dashboard  

Built for **pentesters, red teamers, bug bounty hunters, and cybersecurity learners**.

---

## 🧠 The Problem It Solves

Traditional penetration testing often suffers from:
- Too many tools, too much noise  
- Disconnected findings  
- Manual decision-making fatigue  
- Difficulty deciding *what to exploit next*

**Offensive AI** bridges this gap by converting **raw technical data into structured offensive intelligence**.

---

## 🔁 How the Framework Works (High-Level Flow)

### 1️⃣ Recon & Signal Collection
The framework ingests signals such as:
- Subdomains & endpoints  
- Open ports and services  
- Technology fingerprints  
- HTTP headers & responses  
- Misconfiguration indicators  

All data is **normalised and de-duplicated** to reduce noise.

---

### 2️⃣ Correlation Engine
Related findings are grouped together to build context.

Example:
Exposed admin panel
+ Weak authentication hint
+ Known vulnerable tech stack
= Potential privilege escalation path

This step converts **isolated issues into meaningful attack chains**.

---

### 3️⃣ AI Reasoning Layer (Local LLM)
Using **llama.cpp with GGUF models**, the AI:
- Analyses relationships between findings  
- Mimics real-world attacker logic  
- Suggests the **most likely next attack step**

✔ Fully local  
✔ No cloud dependency  
✔ Privacy-friendly  

This is **decision support**, not blind exploitation.

---

### 4️⃣ Attack Path Generation
The framework structures AI output into:
- Step-by-step attack paths  
- Entry point → lateral movement → impact  
- Priority and likelihood scoring  

Result:
```
Recon → Initial Access → Expansion → Impact
```
---

### 5️⃣ OWASP & Risk Mapping
Each attack path is:
- Mapped to **OWASP Top 10 categories**  
- Ranked based on risk & exploitability  

This makes results **report-ready and management-friendly**.

---

### 6️⃣ Visualisation Layer
All insights are presented through:
- A clean Streamlit dashboard  
- Easy-to-understand attack flows  
- Human-readable explanations  

No messy terminal output — only **clear offensive insight**.

---

## ✨ Key Features

- 🔍 Multi-tool recon aggregation  
- 🧠 AI-generated realistic attack paths  
- 📊 Risk-based prioritisation  
- 🧩 OWASP Top 10 mapping  
- 🌐 Visual attack surface analysis  
- ⚡ Fast Streamlit UI  
- 🖥️ Offline / local-first architecture  

---

## 🧰 Requirements

- Windows 10 / 11  
- Python **3.10+**  
- Git  
- Streamlit  
- llama.cpp (local LLM server)

---

## ⚙️ Installation (Windows – Easy)

```powershell
# 1️⃣ Clone the repository
git clone https://github.com/HackerBlazeX/Offensive-AI-Attack-Path-Visualizer.git
cd Offensive-AI-Attack-Path-Visualizer

# 2️⃣ Install dependencies
pip install -r requirements.txt

# 3️⃣ Start local LLM server (llama.cpp)
.\llama-server.exe -m path\to\model.gguf -c 4096 -t 6 -ngl 35

# 4️⃣ Run the framework
streamlit run Offensive-AI.py

# 5️⃣ Open in browser
http://localhost:8501

⚠️ Important Note

This framework is not an auto-exploitation tool.
It is an AI-assisted offensive decision-support system designed to:

Reduce manual analysis time

Improve attack planning

Enhance learning and reporting quality

🔐 Legal Disclaimer

This project is intended only for authorised security testing, research, and education.
The author is not responsible for misuse or illegal activity.

📄 License

Licensed under the MIT License.
See the LICENSE file for details.

👨‍💻 Author

Dip Kar
Cybersecurity | Offensive Security | AI × Security

⭐ Support

If you find this project useful:

⭐ Star the repository

🧠 Share feedback

🚀 Contribute ideas or improvements


