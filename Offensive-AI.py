import streamlit as st
import socket
import subprocess
import json
from datetime import datetime
from textwrap import dedent
from typing import Dict, Any, Optional, List
import platform
import requests
import os
import pandas as pd
import altair as alt
from concurrent.futures import ThreadPoolExecutor, as_completed

# 🔽 EXTRA
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# =========================
# APP META
# =========================
APP_NAME = "Offensive – AI Attack Path Visualizer"
AUTHOR = "Dip Kar"
VERSION = "v5.8"

# =========================
# 🔥 PAGE CONFIG (MUST BE FIRST STREAMLIT CALL)
# =========================
st.set_page_config(
    page_title=APP_NAME,
    layout="wide"
)

# =========================
# 🎨 UI / THEME FIX (FINAL)
# =========================
def apply_ui_fix():
    st.markdown("""
    <style>

    /* =========================
       APP BACKGROUND
    ========================= */
    .stApp {
        background: radial-gradient(circle at top, #0b0220, #05010f);
    }

    /* =========================
       SIDEBAR
    ========================= */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #05010f, #0b0220);
        box-shadow: 0 0 30px rgba(155, 92, 255, 0.35);
    }

    section[data-testid="stSidebar"] * {
        color: #ffffff !important;
    }

    /* =========================
       MAIN AREA TEXT FIX 🔥
    ========================= */

    /* Checkbox / Radio labels */
    label span {
        color: #eaeaea !important;
        font-weight: 500;
    }

    /* Section titles & markdown text */
    div[data-testid="stMarkdownContainer"] * {
        color: #eaeaea !important;
    }

    /* Expander labels */
    details summary {
        color: #ffffff !important;
        font-weight: 600;
    }

    /* =========================
       HEADINGS
    ========================= */
    h1, h2, h3, h4 {
        color: #ffffff !important;
        text-shadow: 0 0 10px rgba(155,92,255,0.6);
    }

    /* =========================
       INPUT BOX FIX
    ========================= */
    div[data-baseweb="input"] input,
    div[data-baseweb="textarea"] textarea {
        background-color: #f2f2f2 !important;
        color: #000000 !important;
        border-radius: 8px !important;
        border: 1px solid #9b5cff !important;
    }

    input::placeholder {
        color: #666666 !important;
    }

    /* =========================
       CHECKBOX / RADIO ICON
    ========================= */
    input[type="checkbox"], input[type="radio"] {
        accent-color: #9b5cff;
    }

    /* =========================
       BUTTON
    ========================= */
    button[kind="primary"] {
        background: linear-gradient(90deg, #6a00ff, #b700ff);
        color: #ffffff !important;
        border-radius: 8px;
        box-shadow: 0 0 14px rgba(183,0,255,0.6);
        border: none;
    }

    button[kind="primary"]:hover {
        transform: scale(1.03);
        box-shadow: 0 0 22px rgba(183,0,255,0.9);
    }

    </style>
    """, unsafe_allow_html=True)

# =========================
# 🔥 APPLY UI FIX
# =========================
apply_ui_fix()

# =========================
# CONSTANT PATHS (TUMHARE SYSTEM KE HISAB SE)
# =========================

PARAMSPIDER_BASE = r"C:\Users\dipka"
PARAMSPIDER_RESULTS_DIR = os.path.join(PARAMSPIDER_BASE, "results")

# =========================
# LLM CONFIG (local llama.cpp server)
# =========================

LLM_API_URL = "http://localhost:8080/v1/chat/completions"  # local llama.cpp OpenAI-style endpoint


def call_local_llm(prompt: str, backend: str = "Demo (built-in)") -> str:
    """
    backend options:
      - "Demo (built-in)"
      - "Local Llama 3.1 8B Q5"
      - "Local Qwen 2 7B Q5"  (future use)
    """

    # 🔹 Demo mode – works even without local server / model
    if backend.startswith("Demo"):
        header = "🧠 AI Attack Path (demo mode – local LLM connect karne pe real brain use hoga):\n\n"
        body = dedent(
            """
            1️⃣ Reconnaissance  
               - Subdomain, port & tech stack mapping to understand exposed surface.
            2️⃣ Entry Point Identification  
               - Focus on login panels, upload endpoints, APIs & admin paths.
            3️⃣ Vulnerability Exploration  
               - Check for auth issues, access control, injection, input validation gaps.
            4️⃣ Lateral Movement  
               - Pivot from one compromised asset to internal/exposed services.
            5️⃣ Impact & Reporting  
               - Map realistic attack scenarios, estimate impact & suggest mitigations.
            """
        )
        return header + body

    # 🔹 Local llama.cpp server (OpenAI compatible)
    if "Llama" in backend:
        model_name = "local-hermes-3-llama-3.1-8b"
    elif "Qwen" in backend:
        model_name = "local-qwen-2-7b-q5"
    else:
        model_name = "local-hermes-3-llama-3.1-8b"

    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity assistant helping with legal, authorised security testing. "
                    "Explain high-level attack paths, risks, and mitigations. "
                    "Do NOT give exploit code, malware, or any illegal instructions."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.4,
        "max_tokens": 900,
    }

    try:
        resp = requests.post(
    LLM_API_URL,
    json=payload,
    timeout=(60, 600)
)

        resp.raise_for_status()
        data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            return "⚠️ Local LLM ne empty response diya. Request / config check karo."

        text = choices[0].get("message", {}).get("content", "")
        if not text:
            return "⚠️ Local LLM response parse nahi ho paaya. JSON structure check karo."

        return f"🧠 Local LLM ({model_name}):\n\n{text.strip()}"

    except requests.exceptions.ConnectionError:
        return (
            "⚠️ Local LLM server se connect nahi ho paaya.\n"
            "- Kya `llama-server.exe` abhi chal raha hai?\n"
            "- Kya address sahi hai: http://localhost:8080/v1/chat/completions ?\n"
        )
    except Exception as e:
        return f"⚠️ Local LLM error: {e}"


# =========================
# GENERIC COMMAND RUNNER
# =========================

def run_command(cmd: List[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        out = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        return out.strip() or "[i] No output."
    except FileNotFoundError:
        return f"[!] Tool not found: {' '.join(cmd)}"
    except subprocess.TimeoutExpired:
        return f"[!] Command timed out: {' '.join(cmd)}"
    except Exception as e:
        return f"[!] Error running command {' '.join(cmd)}: {e}"


# =========================
# BASIC RECON
# =========================

def resolve_domain(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def basic_recon(domain: str) -> Dict[str, Any]:
    ip = resolve_domain(domain)
    is_windows = platform.system().lower().startswith("win")
    ping_cmd = ["ping", "-n" if is_windows else "-c", "2", domain]
    nslookup_out = run_command(["nslookup", domain], timeout=20)
    ping_out = run_command(ping_cmd, timeout=20)
    return {
        "domain": domain,
        "ip": ip,
        "nslookup": nslookup_out,
        "ping": ping_out,
    }


# =========================
# HTTP/HTTPS AUTO-DETECT HELPER
# =========================

def build_url(domain_or_url: str, force_https: bool = False) -> str:
    """
    - Agar user already http:// ya https:// de de to usko respect karo.
    - Warna pehle https try karo, agar fail ho to http use karo.
    """
    d = (domain_or_url or "").strip()

    if not d:
        return ""

    if d.startswith("http://") or d.startswith("https://"):
        return d

    # Only domain diya gaya
    if force_https:
        return f"https://{d}"

    try:
        # SSL verify false rakha hai taaki self-signed, lab env etc. pe bhi kaam kare
        requests.get(f"https://{d}", timeout=4, verify=False)
        return f"https://{d}"
    except Exception:
        return f"http://{d}"
    
def normalize_sqlmap_url(url: str) -> str:
    url = (url or "").strip()
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return "http://" + url

# =========================
# PARAMSPIDER + AUTO PIPELINE HELPERS
# =========================

def collect_paramspider_urls(domain: str) -> List[str]:
    """
    ParamSpider ko C:\\Users\\dipka se run karke
    C:\\Users\\dipka\\results\\{domain}.txt se URLs uthata hai.
    """
    try:
        cmd = ["ParamSpider", "-d", domain]
        result = subprocess.run(
            cmd,
            cwd=PARAMSPIDER_BASE,
            capture_output=True,
            text=True,
            timeout=900,
        )
        _ = result
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []

    output_file = os.path.join(PARAMSPIDER_RESULTS_DIR, f"{domain}.txt")
    if not os.path.exists(output_file):
        return []

    urls: List[str] = []
    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read().splitlines()
    except Exception:
        return []

    for u in raw:
        u = u.strip()
        if not u:
            continue
        if not u.startswith("http"):
            continue
        if "=" not in u:
            continue

        # ✅ FIX: FUZZ ko real value se replace
        u = u.replace("FUZZ", "test")

        urls.append(u)

    return list(sorted(set(urls)))

def run_paramspider(domain: str) -> str:
    urls = collect_paramspider_urls(domain)
    if not urls:
        return (
            "[!] ParamSpider ne koi usable URL nahi diya ya output file nahi mili.\n"
            "    - Check karo: `ParamSpider -h` chal raha hai na?\n"
            "    - Aur results folder: C:\\Users\\dipka\\results\\*.txt"
        )

    sample = "\n".join(urls[:30])
    return (
        f"[+] ParamSpider collected {len(urls)} parameterised URLs for {domain}.\n\n"
        f"Sample (max 30):\n{sample}"
    )


def sqlmap_confirm_mode(url: str) -> str:
    # URL ko safe banata hai (http/https issue fix)
    url = normalize_sqlmap_url(url)

    cmd = [
        "sqlmap", "-u", url,
        "--batch",
        "--random-agent",
        "--level", "3",
        "--risk", "2",
        "--technique", "BEUSTQ",
        "--threads", "1",
        "--time-sec", "5",
        "--timeout", "15",
        "--retries", "2",
        "--current-db",
        "--banner"
    ]
    return run_command(cmd, timeout=900)



def sqlmap_waf_mode(url: str) -> str:
    cmd = [
        "sqlmap", "-u", url,
        "--batch",
        "--random-agent",
        "--level", "4",
        "--risk", "2",
        "--technique", "BEU",
        "--tamper", "space2comment,randomcase",
        "--threads", "1",
        "--time-sec", "3",
        "--banner",
        "--current-db",
        "--ignore-ssl-errors"
    ]
    return run_command(cmd, timeout=600)


def auto_sqlmap_smart(url: str) -> str:
    url = normalize_sqlmap_url(url)

    # 🔥 Extract parameters
    if "?" not in url:
        return "[!] No parameters found in URL – SQLMap skipped."

    param_part = url.split("?", 1)[1]
    base = url.split("?", 1)[0]
    params = param_part.split("&")

    combined_output = []

    for p in params:
        if "=" not in p:
            continue

        name, val = p.split("=", 1)
        test_url = f"{base}?{name}={val}"

        out = sqlmap_confirm_mode(test_url)

        combined_output.append(
            f"--- PARAMETER TESTED: {name} ---\n{out}\n"
        )

        # 🔥 Stop early if confirmed
        if any(x in out.lower() for x in [
            "sql injection vulnerability",
            "the back-end dbms",
            "current database"
        ]):
            return "✅ SQL Injection CONFIRMED (per-parameter)\n\n" + "\n".join(combined_output)

    return "❌ SQL Injection NOT confirmed (per-parameter scan)\n\n" + "\n".join(combined_output)

# =========================
# XSStrike – FINAL SMART XSS ENGINE
# =========================

def run_xsstrike_safe(url: str) -> str:
    """XSStrike Safe Mode (default, fast, real-world)"""
    cmd = [
        "xsstrike",
        "-u", url,
        "--crawl",
        "--fuzzer",
        "--path",
        "--timeout", "12",
        "-t", "4",
        "--headers",
        "User-Agent: Security-Scanner"
    ]
    return run_command(cmd, timeout=480)


def run_xsstrike_waf(url: str) -> str:
    """XSStrike WAF / Filter Bypass Mode (fallback)"""
    cmd = [
        "xsstrike",
        "-u", url,
        "--crawl",
        "--fuzzer",
        "--blind",
        "--timeout", "18",
        "-t", "2",
        "--headers",
        "User-Agent: Mozilla/5.0"
    ]
    return run_command(cmd, timeout=720)


# ======================================================
# XSS ANALYSIS (SIGNAL BASED)
# ======================================================

def analyze_xss_output(output: str) -> dict:
    out = output.lower()

    # ✅ REAL EXECUTION (ONLY HARD PROOF)
    if any(x in out for x in [
        "payload executed",
        "xss confirmed",
        "javascript executed",
        "execution successful"
    ]):
        return {
            "status": "XSS CONFIRMED",
            "confidence": 0.9,
            "severity": "HIGH",
            "summary": "JavaScript payload executed in browser context",
            "next_steps": [
                "Capture proof of execution",
                "Identify injection context",
                "Assess business impact",
                "Prepare bug bounty report"
            ]
        }

    # ⚠️ FILTERED / WAF BLOCKED
    if any(x in out for x in ["[blocked]", "filtered", "sanitized", "waf"]):
        return {
            "status": "XSS FILTERED",
            "confidence": 0.4,
            "severity": "LOW",
            "summary": "Payload blocked or sanitized by WAF / input filtering",
            "next_steps": [
                "Try encoding or obfuscation",
                "Test alternate parameters",
                "Manual review for bypass"
            ]
        }

    # ⚠️ REFLECTION / CONTEXT WITHOUT EXECUTION
    if any(x in out for x in [
        "reflected",
        "reflection",
        "html injected",
        "context break",
        "sink reached"
    ]):
        return {
            "status": "POTENTIAL XSS",
            "confidence": 0.6,
            "severity": "MEDIUM",
            "summary": "Input reflected but no JavaScript execution observed",
            "next_steps": [
                "Identify reflection context",
                "Try context-specific payloads",
                "Manual browser testing"
            ]
        }

    # ❌ NOTHING FOUND
    return {
        "status": "NO XSS FOUND",
        "confidence": 0.1,
        "severity": "INFO",
        "summary": "No XSS indicators detected",
        "next_steps": []
    }

# ======================================================
# STRONG CONFIRMATION (NO PAYLOAD EXECUTION)
# ======================================================

def confirm_xss_from_output(url: str, output: str) -> str:
    out = output.lower()

    # 🚫 If payloads are blocked/sanitized → never CONFIRMED
    if any(x in out for x in ["[blocked]", "filtered", "sanitized", "waf"]):
        return f"⚠️ [FILTERED] XSS payload blocked on {url}"

    # ✅ Real execution indicators (VERY IMPORTANT)
    execution_signals = [
        "payload executed",
        "xss confirmed",
        "javascript executed",
        "alert executed",
        "confirm executed",
        "execution successful"
    ]

    if any(sig in out for sig in execution_signals):
        return f"✅ [CONFIRMED] XSS is exploitable on {url}"

    # ⚠️ Reflection without execution
    reflection_signals = [
        "reflected",
        "reflection",
        "html injected",
        "context break",
        "sink reached"
    ]

    if any(sig in out for sig in reflection_signals):
        return f"⚠️ [POTENTIAL] XSS reflection detected on {url}"

    return f"❌ No XSS detected on {url}"

# ======================================================
# AUTO SMART XSS (SAFE + WAF MODE)
# ======================================================

def auto_xss_smart(url: str) -> dict:
    url = normalize_sqlmap_url(url)

    if "?" not in url:
        return {
            "status": "SKIPPED",
            "confidence": 0.0,
            "severity": "INFO",
            "summary": "No parameters found in URL",
            "raw_output": ""
        }

    base, param_part = url.split("?", 1)
    params = param_part.split("&")
    combined_raw = []

    for p in params:
        if "=" not in p:
            continue

        name, val = p.split("=", 1)
        test_url = f"{base}?{name}={val}"

        # ----------------------
        # SAFE MODE
        # ----------------------
        raw = run_xsstrike_safe(test_url)
        analysis = analyze_xss_output(raw)

        confirmation = confirm_xss_from_output(test_url, raw)
        analysis["confirmation"] = confirmation

        combined_raw.append(
            f"--- SAFE MODE PARAMETER: {name} ---\n{raw}\n"
        )

        if "CONFIRMED" in confirmation or "POTENTIAL" in confirmation:
            analysis["raw_output"] = "\n".join(combined_raw)
            return analysis

        # ----------------------
        # WAF / FILTER MODE
        # ----------------------
        raw = run_xsstrike_waf(test_url)
        analysis = analyze_xss_output(raw)

        confirmation = confirm_xss_from_output(test_url, raw)
        analysis["confirmation"] = confirmation

        combined_raw.append(
            f"--- WAF MODE PARAMETER: {name} ---\n{raw}\n"
        )

        if "CONFIRMED" in confirmation or "POTENTIAL" in confirmation:
            analysis["raw_output"] = "\n".join(combined_raw)
            return analysis

    # ----------------------
    # FINAL FALLBACK
    # ----------------------
    return {
        "status": "NO XSS FOUND",
        "confidence": 0.2,
        "severity": "INFO",
        "summary": "No exploitable XSS detected (per-parameter scan)",
        "raw_output": "\n".join(combined_raw)
    }

def full_auto_pipeline(domain: str, max_urls: int = 10, max_workers: int = 4) -> dict:
    """
    ParamSpider → SQLMap → XSStrike pipeline
    FAST MODE: limited URLs + parallel execution
    """
    results: Dict[str, Any] = {
        "paramspider_urls": [],
        "tested_urls": [],
        "sqlmap": {},
        "xsstrike": {},
    }

    urls = collect_paramspider_urls(domain)
    results["paramspider_urls"] = urls

    if not urls:
        return results

    safe_urls = urls[:max_urls]
    results["tested_urls"] = safe_urls

    def run_for_url(u: str):
        """Single URL ke liye SQLMap + XSStrike"""
        sql_out = auto_sqlmap_smart(u)
        xss_out = auto_xss_smart(u)
        return u, sql_out, xss_out

    # ✅ Parallel execution
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(run_for_url, u): u for u in safe_urls}

        for fut in as_completed(future_map):
            u = future_map[fut]
            try:
                _, sql_out, xss_out = fut.result()
                results["sqlmap"][u] = sql_out
                results["xsstrike"][u] = xss_out
            except Exception as e:
                err = f"[!] Auto pipeline error for URL {u}: {e}"
                results["sqlmap"][u] = err
                results["xsstrike"][u] = err

    return results

# =========================
# TOOL WRAPPERS – CORE
# =========================

def run_nmap(domain: str) -> str:
    cmd = ["nmap", "-sV", "-T4", "-Pn", "-F", domain]
    return run_command(cmd, timeout=300)


def run_subfinder(domain: str) -> str:
    cmd = ["subfinder", "-silent", "-d", domain]
    return run_command(cmd, timeout=180)


def run_httpx(domain: str) -> str:
    url = build_url(domain)
    cmd = [
        "httpx",
        "-u", url,
        "-title",
        "-status-code",
        "-tech-detect",
        "-no-color",
        "-silent",
    ]
    return run_command(cmd, timeout=120)


def run_nuclei(domain: str) -> str:
    url = build_url(domain)  # returns http:// or https://

    cmd = [
        "nuclei",
        "-u", url,
        "-severity", "critical,high,medium",
        "-c", "25",          # concurrency (balanced)
        "-rl", "20",         # rate limit (safe)
        "-timeout", "10",
        "-retries", "1",
        "-stats",
    ]

    return run_command(cmd, timeout=900)


def run_ffuf(domain: str, wordlist: str, extensions: str = "") -> str:
    if not wordlist:
        return (
            "[!] FFUF skipped: wordlist path not provided.\n"
            "    Tip: Fill FFUF wordlist path in the sidebar (e.g. C:/wordlists/common.txt)."
        )
    base = build_url(domain)
    base = base.rstrip("/")
    url = f"{base}/FUZZ"
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-mc", "200,301,302,403"]
    if extensions:
        cmd += ["-e", extensions]
    return run_command(cmd, timeout=900)


def run_dirsearch(domain: str, wordlist: str) -> str:
    if not wordlist:
        return (
            "[!] Dirsearch skipped: wordlist path not provided.\n"
            "    Tip: Fill Dirsearch wordlist path in the sidebar."
        )
    url = build_url(domain)
    cmd = [
    "dirsearch",
    "-u", url,
    "-w", wordlist,
    "-t", "50",
]
    return run_command(cmd, timeout=900)


def run_xsstrike(target: str) -> str:
    url = build_url(target)
    cmd = [
        "xsstrike",
        "-u", url,
        "--crawl",
        "--skip-dom",
        "--fuzzer",
        "--path",
        "--blind",
    ]
    return run_command(cmd, timeout=600)


def run_sqlmap(target_url: str) -> str:
    if "?" not in target_url:
        return "[!] SQLMap skipped: Please provide a full URL with parameters (e.g., https://site.com/page.php?id=1)."
    cmd = [
        "sqlmap",
        "-u", target_url,
        "--batch",
        "--smart",
        "--random-agent",
        "--level", "3",
        "--risk", "2",
        "--ignore-ssl-errors",
        "--threads", "4",
    ]
    return run_command(cmd, timeout=300)
def verify_vulnerability(v_type: str, url: str, output: str) -> str:
    """Verifies tool output to ensure it's not a False Positive"""
    if v_type == "XSS":
    # Signal-based confirmation (NO payload execution)
     xss_signals = [
        "reflected",
        "reflection",
        "<script",
        "onerror=",
        "onload=",
        "alert(",
        "svg"
    ]

    score = sum(1 for s in xss_signals if s in output.lower())

    if score >= 2:
        return f"✅ [CONFIRMED] XSS is Real on {url}"
    elif score == 1:
        return f"⚠️ [POTENTIAL] XSS signal detected on {url}"
    else:
        return f"❌ No XSS detected on {url}"

    
    if v_type == "SQLi":
        # Check if output contains database names or version strings
        if any(x in output.lower() for x in ["database:", "version:", "oracle", "mysql", "get_user"]):
            return f"✅ [CONFIRMED] SQLi is exploitable on {url}"
            
    return "⚠️ [POTENTIAL] Manual check required."
def predator_js_deep_crawl(domain: str) -> List[Dict[str, str]]:
    """Crawls all JS files of the domain and extracts hardcoded credentials"""
    st.write(f"🔍 [Predator] Deep Analysis of JavaScript files on {domain}...")
    leaks = []
    regex_list = {
        "AWS_KEY": r"AKIA[0-9A-Z]{16}",
        "GOOGLE_API": r"AIza[0-9A-Za-z-_]{35}",
        "FIREBASE": r"https://.*\.firebaseio\.com",
        "GITHUB_TOKEN": r"ghp_[a-zA-Z0-9]{36}",
        "STRIPE_KEY": r"sk_live_[0-9a-zA-Z]{24}",
        "S3_BUCKET": r"[a-z0-9.-]+\.s3\.amazonaws\.com"
    }
    try:
        base_url = build_url(domain)
        r = requests.get(base_url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        js_files = [urljoin(base_url, s.get('src')) for s in soup.find_all('script', src=True)]
        
        for js_url in js_files:
            content = requests.get(js_url, timeout=5, verify=False).text
            for key_name, pattern in regex_list.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    leaks.append({"File": js_url, "Type": key_name, "Value": match})
    except Exception as e:
        st.error(f"JS Scan Error: {e}")
    return leaks


# =========================
# EXTRA TOOLS – OFFENSIVE VIEW
# =========================

def run_whois(domain: str) -> str:
    cmd = ["whois", domain]
    return run_command(cmd, timeout=60)


def run_traceroute(domain: str) -> str:
    is_windows = platform.system().lower().startswith("win")
    if is_windows:
        cmd = ["tracert", domain]
    else:
        cmd = ["traceroute", domain]
    return run_command(cmd, timeout=180)


def run_curl_headers(domain: str) -> str:
    url = build_url(domain)
    is_windows = platform.system().lower().startswith("win")
    null_sink = "NUL" if is_windows else "/dev/null"
    cmd = ["curl", "-s", "-D", "-", "-o", null_sink, url]
    return run_command(cmd, timeout=60)


def run_nikto(domain: str) -> str:
    """
    FINAL & STABLE Nikto runner
    - Input: DOMAIN ONLY (example.com)
    - -p conflict kabhi nahi
    - Test sites → full output
    - Real sites → clean fallback (no scary errors)
    - No repeated changes needed
    """

    nikto_path = r"C:\Users\dipka\nikto\program\nikto.pl"

    # 🔹 force domain only (NO protocol, NO path)
    domain = (
        domain.strip()
        .replace("http://", "")
        .replace("https://", "")
        .split("/")[0]
    )

    scans = [
        {
            "label": "HTTPS",
            "cmd": [
                "perl", nikto_path,
                "-h", domain,
                "-ssl",
                "-p", "443",
                "-Tuning", "x",
                "-nointeractive",
                "-timeout", "45",
                "-useragent", "Mozilla/5.0"
            ]
        },
        {
            "label": "HTTP",
            "cmd": [
                "perl", nikto_path,
                "-h", domain,
                "-p", "80",
                "-Tuning", "x",
                "-nointeractive",
                "-timeout", "45",
                "-useragent", "Mozilla/5.0"
            ]
        }
    ]

    for scan in scans:
        output = run_command(scan["cmd"], timeout=300)  # 5 min max

        # ✅ success (real findings OR clean output)
        if output:
            if "The -port option cannot be used" in output:
                return (
                    f"===== NIKTO {scan['label']} RESULT =====\n"
                    "⚠️ Internal Nikto option conflict avoided.\n"
                    "Scan safely aborted."
                )

            if "Command timed out" in output:
                return (
                    f"===== NIKTO {scan['label']} RESULT =====\n"
                    "⚠️ Scan timed out.\n"
                    "Reason: Target is slow or protected by WAF.\n"
                    "This is NORMAL for real production sites.\n"
                    "Recommendation: rely on httpx / nuclei / manual testing."
                )

            if "Unable to connect" not in output:
                return (
                    f"===== NIKTO {scan['label']} RESULT =====\n"
                    f"{output.strip()}"
                )

    # 🔁 final fallback (always something meaningful)
    return (
        "===== NIKTO RESULT =====\n"
        "⚠️ Nikto could not complete scan.\n"
        "Target likely hardened or rate-limited.\n"
        "No exploitable web server misconfigurations detected via Nikto."
    )

# =========================
# ATTACK SURFACE + RISK
# =========================

def build_attack_surface_summary(recon: Dict[str, Any], tool_results: Dict[str, str]) -> Dict[str, Any]:
    surface = {
        "domain": recon.get("domain"),
        "ip": recon.get("ip"),
        "assets": [],
        "notes": [],
        "tools_ran": [k for k, v in tool_results.items() if v],
    }
    if recon.get("ip"):
        surface["assets"].append(
            {
                "type": "host",
                "label": f"{recon['domain']} ({recon['ip']})",
                "risk": "medium",
                "reason": "Resolvable host, further port/service scanning recommended.",
            }
        )
    else:
        surface["notes"].append("Domain did not resolve to an IP; target may be offline or misconfigured.")

    if recon.get("nslookup"):
        surface["notes"].append("Basic DNS info collected (nslookup output available).")

    if recon.get("ping") and "[!]" not in recon["ping"]:
        surface["notes"].append("Host responded to ping; likely reachable from your network.")
    else:
        surface["notes"].append("Ping failed or ICMP may be blocked.")

    if tool_results.get("nmap") and "[!]" not in tool_results["nmap"]:
        surface["notes"].append("Nmap scan completed; open ports/services may exist.")

    if tool_results.get("nuclei") and "[!]" not in tool_results["nuclei"]:
        surface["notes"].append("Nuclei templates executed; check output for misconfigurations or known vulns.")

    if tool_results.get("subfinder") and "[!]" not in tool_results["subfinder"]:
        surface["notes"].append("Subdomains discovered; attack surface broader than a single host.")

    if tool_results.get("whois") and "[!]" not in tool_results["whois"]:
        surface["notes"].append("WHOIS data collected; registrar, contact and nameserver details available.")

    if tool_results.get("traceroute") and "[!]" not in tool_results["traceroute"]:
        surface["notes"].append("Traceroute completed; network path towards the target observed.")

    if tool_results.get("nikto") and "[!]" not in tool_results["nikto"]:
        surface["notes"].append("Nikto web server scan ran; check for low-hanging misconfigurations and info leak.")

    if tool_results.get("paramspider") and "[!]" not in tool_results["paramspider"]:
        surface["notes"].append("ParamSpider discovered parameterised URLs; deeper input-based attack surface exists.")

    return surface


def estimate_risk(surface: Dict[str, Any], tool_results: Dict[str, str]) -> Dict[str, Any]:
    """
    Rough risk score based on Nmap + Nuclei output.
    Educational / visualisation only.
    """
    score = 10
    label = "Low"

    nmap_out = tool_results.get("nmap", "") or ""
    nuclei_out = tool_results.get("nuclei", "") or ""

    open_count = nmap_out.lower().count("open")
    score += min(open_count * 5, 40)

    low_n = nuclei_out.lower()
    crit = low_n.count("critical")
    high = low_n.count("high")
    medium = low_n.count("medium")

    score += min(crit * 12 + high * 8 + medium * 4, 50)

    score = max(0, min(score, 100))

    if score >= 80:
        label = "High"
    elif score >= 50:
        label = "Medium"
    else:
        label = "Low"

    return {
        "score": score,
        "label": label,
        "details": {
            "open_ports_estimate": open_count,
            "nuclei_critical": crit,
            "nuclei_high": high,
            "nuclei_medium": medium,
        },
    }


def attack_surface_to_prompt(surface: Dict[str, Any], tool_results: Dict[str, str], auto_pipeline: Optional[dict] = None) -> str:
    summary_lines = [
        f"Domain: {surface.get('domain')}",
        f"IP: {surface.get('ip')}",
        "",
        "Tools executed:",
    ]
    if surface.get("tools_ran"):
        for t in surface["tools_ran"]:
            summary_lines.append(f"- {t}")
    else:
        summary_lines.append("- (Only basic DNS/ping)")
    summary_lines.append("")
    summary_lines.append("Assets:")
    for a in surface.get("assets", []):
        summary_lines.append(
            f"- [{a.get('risk', 'unknown').upper()}] {a.get('type')}: {a.get('label')} ({a.get('reason')})"
        )
    if surface.get("notes"):
        summary_lines.append("\nNotes:")
        for n in surface["notes"]:
            summary_lines.append(f"- {n}")

    if auto_pipeline:
        urls = auto_pipeline.get("paramspider_urls", [])
        tested = auto_pipeline.get("tested_urls", [])
        summary_lines.append("\nParamSpider / SQLMap / XSStrike auto-pipeline summary:")
        summary_lines.append(f"- Total ParamSpider URLs with params: {len(urls)}")
        summary_lines.append(f"- URLs tested with SQLMap / XSStrike: {len(tested)}")

    summary_lines.append(
        dedent(
            """
            Based on this limited attack surface and the tools that were run, propose a high-level,
            educational attack path that a *legal, authorised* security tester might explore. Focus on:
            - Recon and mapping (including ports, subdomains, technologies if available)
            - Possible entry points and interesting services
            - What to investigate for vulnerabilities (including any input/parameter-based issues)
            - How to document impact and remediation

            Do NOT provide exploit code or illegal instructions.
            """
        )
    )
    return "\n".join(summary_lines)


# =========================
# NEW HELPERS – PARSERS
# =========================

def parse_nmap_open_ports(nmap_out: str) -> List[Dict[str, Any]]:
    ports: List[Dict[str, Any]] = []
    if not nmap_out:
        return ports

    for line in nmap_out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 3 and "/" in parts[0] and parts[1] == "open":
            port_proto = parts[0]
            service = parts[2]
            try:
                port_str, proto = port_proto.split("/")
            except ValueError:
                continue
            try:
                port_int = int(port_str)
            except ValueError:
                continue
            ports.append(
                {
                    "port": port_int,
                    "proto": proto,
                    "service": service,
                }
            )
    return ports


def parse_subfinder_output(subfinder_out: str, target_domain: str) -> List[str]:
    if not subfinder_out:
        return []
    subs: List[str] = []
    for line in subfinder_out.splitlines():
        s = line.strip()
        if not s:
            continue
        if target_domain in s:
            subs.append(s)
    return sorted(set(subs))


# =========================
# VULNERABILITY CORRELATION + AI RANKING
# =========================

def correlate_vulnerabilities(
    target_domain: str,
    tool_results: Dict[str, str],
    auto_pipeline: Optional[dict],
    ports: List[Dict[str, Any]],
    subdomains: List[str],
) -> List[Dict[str, Any]]:
    """
    Tools ke outputs ko combine karke high-level "hotspots" banata hai.
    Koi exploit code nahi, sirf signals correlate karta hai.
    """
    correlated: List[Dict[str, Any]] = []

    # 1) Host-level network exposure (ports)
    if ports:
        correlated.append(
            {
                "asset": target_domain,
                "category": "Host / Network",
                "signals": [
                    f"{len(ports)} open port(s) from Nmap",
                ],
                "score": min(len(ports), 10),
                "note": "More exposed services usually mean broader attack surface.",
            }
        )

    # 2) Nuclei findings
    nuclei_out = (tool_results.get("nuclei") or "").lower()
    if nuclei_out and "[!]" not in nuclei_out:
        crit = nuclei_out.count("critical")
        high = nuclei_out.count("high")
        medium = nuclei_out.count("medium")
        total = crit + high + medium
        if total > 0:
            score = min(crit * 3 + high * 2 + medium, 10)
            sev_parts = []
            if crit:
                sev_parts.append(f"{crit} critical")
            if high:
                sev_parts.append(f"{high} high")
            if medium:
                sev_parts.append(f"{medium} medium")
            sev_text = ", ".join(sev_parts)
            correlated.append(
                {
                    "asset": f"{build_url(target_domain)}",
                    "category": "Web / Known vulns",
                    "signals": [f"Nuclei templates triggered: {sev_text}"],
                    "score": score,
                    "note": "Template-based findings; require manual validation before report.",
                }
            )

    # 3) ParamSpider + SQLMap + XSStrike (AUTO PIPELINE) ✅ FIXED
    if auto_pipeline:
        for url in auto_pipeline.get("tested_urls", []):

            raw_sql = auto_pipeline.get("sqlmap", {}).get(url, "")
            raw_xss = auto_pipeline.get("xsstrike", {}).get(url, "")

            s_sql = str(raw_sql).lower()

            if isinstance(raw_xss, dict):
                raw_xss = json.dumps(raw_xss)
            s_xss = str(raw_xss).lower()

            if not s_sql and not s_xss:
                continue

            signals = []
            score = 0

            if s_sql:
                if any(k in s_sql for k in ["sql injection", "union", "current database", "back-end dbms"]):
                    signals.append("SQLMap output contains strong SQL injection indicators.")
                    score += 4
                elif any(k in s_sql for k in ["heuristic", "possible", "might be injectable"]):
                    signals.append("SQLMap heuristic / possible SQLi indicators.")
                    score += 2

            if s_xss:
                if any(k in s_xss for k in ["xss", "payload", "vulnerable"]):
                    signals.append("XSStrike output indicates potential XSS behaviour.")
                    score += 4
                elif any(k in s_xss for k in ["reflected", "context", "sink"]):
                    signals.append("XSStrike found interesting reflection / context patterns.")
                    score += 2

            if not signals:
                continue

            correlated.append(
                {
                    "asset": url,
                    "category": "Parameterised URL",
                    "signals": signals,
                    "score": min(score, 10),
                    "note": "Parameter-based behaviour identified; requires manual verification within scope.",
                }
            )

    # 4) Nikto findings
    nikto_out = (tool_results.get("nikto") or "").lower()
    if nikto_out and "[!]" not in nikto_out:
        sigs = []
        if "outdated" in nikto_out or "obsolete" in nikto_out:
            sigs.append("Outdated / obsolete components mentioned by Nikto.")
        if "directory indexing" in nikto_out or "indexes" in nikto_out:
            sigs.append("Possible directory indexing / listing issues.")
        if "trace" in nikto_out and "enabled" in nikto_out:
            sigs.append("TRACE HTTP method appears enabled.")
        if not sigs:
            sigs.append("Nikto reported potential web server / configuration issues.")
        correlated.append(
            {
                "asset": f"{build_url(target_domain)}",
                "category": "Web server / Config",
                "signals": sigs,
                "score": min(len(sigs) * 2, 8),
                "note": "Often low-to-medium severity but useful for attack chaining.",
            }
        )

    # 5) Subdomain footprint
    if subdomains and len(subdomains) >= 3:
        correlated.append(
            {
                "asset": f"*.{target_domain}",
                "category": "Subdomain footprint",
                "signals": [f"{len(subdomains)} subdomains discovered via Subfinder."],
                "score": min(len(subdomains) // 3, 7),
                "note": "Staging/dev/forgotten subdomains may expose higher-risk misconfigurations.",
            }
        )

    return correlated

def rank_findings(correlated: List[Dict[str, Any]], risk_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Simple AI-style scoring: score -> priority label.
    """
    ranked = []
    for item in correlated:
        score = int(item.get("score", 0))
        if score >= 8:
            prio = "Critical"
        elif score >= 5:
            prio = "High"
        elif score >= 3:
            prio = "Medium"
        else:
            prio = "Low"
        ranked.append(
            {
                "asset": item.get("asset"),
                "category": item.get("category"),
                "score": score,
                "priority": prio,
                "signals": item.get("signals", []),
                "note": item.get("note", ""),
            }
        )

    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked


def build_ai_ranking_comment(
    ranked_findings: List[Dict[str, Any]],
    risk_info: Dict[str, Any],
    backend: str,
) -> str:
    """
    AI-powered short explanation of priority.
    Demo backend: local summary.
    Local backend: LLM se concise bullet view.
    """
    if not ranked_findings:
        return "Filhaal koi strong correlated hotspot nahi mila. Zyada tools enable karke scan dobara chalao for richer signals."

    # Local summary string
    lines = []
    lines.append(
        f"Overall rough risk score: {risk_info.get('score', 0)}/100 – {risk_info.get('label', 'Unknown')}."
    )
    lines.append("Top priority hotspots (local scoring based):")
    for idx, fnd in enumerate(ranked_findings[:5], start=1):
        sig_preview = "; ".join(fnd["signals"][:2])
        lines.append(
            f"{idx}. [{fnd['priority']}] {fnd['asset']}  "
            f"(category: {fnd['category']}, score: {fnd['score']}/10)  -> {sig_preview}"
        )
    base_summary = "\n".join(lines)

    if backend.startswith("Demo"):
        return base_summary

    # Local LLM explanation
    prompt = dedent(
        """
        You are assisting a legal security tester. Here is a list of correlated hotspots with local scores.
        Summarise in 4–6 concise bullets:
        - which 2–3 assets should be tested first
        - why they are top priority
        - what kind of issues they likely relate to (only high-level categories, no exploits)
        - 1–2 reminders about scope & safe testing.

        Hotspots:
        """
    ) + "\n" + base_summary

    ai_reply = call_local_llm(prompt, backend=backend)
    return ai_reply


# =========================
# OWASP TOP 10 MAPPING MODULE (approx)
# =========================

def _owasp_level_from_score(score: int) -> str:
    if score >= 3:
        return "High"
    elif score == 2:
        return "Medium"
    elif score == 1:
        return "Low"
    else:
        return "None"


def build_owasp_mapping(
    target_domain: str,
    tool_results: Dict[str, str],
    correlated_findings: List[Dict[str, Any]],
    auto_pipeline: Optional[dict],
) -> List[Dict[str, Any]]:
    """
    OWASP Top 10 (approx) mapping – signal based, exploit-less.
    Sirf high-level idea deta hai ki kaun se areas touch ho rahe hain.
    """
    sqlmap_out = (tool_results.get("sqlmap") or "").lower()
    xsstrike_out = (tool_results.get("xsstrike") or "").lower()
    nuclei_out = (tool_results.get("nuclei") or "").lower()
    nikto_out = (tool_results.get("nikto") or "").lower()
    httpx_out = (tool_results.get("httpx") or "").lower()
    dirsearch_out = (tool_results.get("dirsearch") or "").lower()

    total_param_urls = 0
    if auto_pipeline:
        total_param_urls = len(auto_pipeline.get("paramspider_urls", []))

    # Signals
    inj_score = 0
    inj_signals: List[str] = []
    xss_score = 0
    xss_signals: List[str] = []
    miscfg_score = 0
    miscfg_signals: List[str] = []
    access_score = 0
    access_signals: List[str] = []
    auth_score = 0
    auth_signals: List[str] = []

    # Injection (SQLi, other parameter issues)
    if "sql injection" in sqlmap_out or "union query" in sqlmap_out:
        inj_score += 2
        inj_signals.append("SQLMap output mentions SQL injection/union query hints.")
    if total_param_urls > 0:
        inj_score += 1
        inj_signals.append(f"ParamSpider found {total_param_urls} parameterised URLs (input surface).")
    for f in correlated_findings:
        if f.get("category") == "Parameterised URL":
            inj_score += 1
            inj_signals.append("Correlated parameterised URL hotspot (SQLi/XSS signals).")

    # XSS (still part of Injection family, but highlighted)
    if "xss" in xsstrike_out or "payload" in xsstrike_out or "vulnerable" in xsstrike_out:
        xss_score += 2
        xss_signals.append("XSStrike hints at potential XSS behaviour / reflections.")
    for f in correlated_findings:
        if f.get("category") == "Parameterised URL":
            if any("xss" in s.lower() for s in f.get("signals", [])):
                xss_score += 1
                xss_signals.append("Correlated hotspot signals XSS-like behaviour.")

    # Security Misconfiguration – Nikto, Nuclei, dirsearch
    if nikto_out and "[!]" not in nikto_out:
        miscfg_score += 1
        miscfg_signals.append("Nikto web server scan reported possible misconfigurations.")
        if "outdated" in nikto_out or "obsolete" in nikto_out:
            miscfg_score += 1
            miscfg_signals.append("Nikto mentions outdated/obsolete components.")
        if "directory indexing" in nikto_out or "indexes" in nikto_out:
            miscfg_score += 1
            miscfg_signals.append("Directory indexing/listing patterns seen.")
    if nuclei_out and "[!]" not in nuclei_out:
        miscfg_score += 1
        miscfg_signals.append("Nuclei templates triggered (config / CVE templates).")
    if dirsearch_out:
        miscfg_score += 1
        miscfg_signals.append("Dirsearch discovered hidden paths/directories (potential misconfig or sensitive files).")
    for f in correlated_findings:
        if "config" in (f.get("category") or "").lower():
            miscfg_score += 1
            miscfg_signals.append("Correlated config-related hotspot from Nikto/Nuclei.")

    # Broken Access Control – heuristics from text
    if "access control" in nuclei_out or "unauthorized" in nuclei_out or "forbidden" in nuclei_out:
        access_score += 1
        access_signals.append("Nuclei output references access control / forbidden patterns.")
    for f in correlated_findings:
        sig_txt = " ".join(f.get("signals", [])).lower()
        if "idor" in sig_txt or "access" in sig_txt or "authorization" in sig_txt:
            access_score += 1
            access_signals.append("Correlated hotspot text hints at IDOR/access control themes.")
            break

    # Identification & Authentication – login/admin/auth hints
    combined_web_text = " ".join([httpx_out, dirsearch_out, nikto_out])
    if any(k in combined_web_text for k in ["login", "signin", "auth", "session", "admin"]):
        auth_score += 1
        auth_signals.append("Login/admin/auth-related endpoints appear in web tooling output.")
    if "basic realm" in combined_web_text or "www-authenticate" in combined_web_text:
        auth_score += 1
        auth_signals.append("HTTP auth / realm headers observed (auth surface).")

    mapping: List[Dict[str, Any]] = []

    # A01 – Broken Access Control
    mapping.append(
        {
            "id": "A01",
            "name": "Broken Access Control",
            "level": _owasp_level_from_score(access_score),
            "signals": access_signals or ["No strong access control indicators from current scan."],
        }
    )

    # A03 – Injection (SQLi/XSS/Input)
    inj_total_score = min(inj_score + xss_score, 5)
    inj_all_signals = []
    inj_all_signals.extend(inj_signals)
    if xss_signals:
        inj_all_signals.append("XSS-style behaviour indicators from XSStrike / parameter hotspots.")
    mapping.append(
        {
            "id": "A03",
            "name": "Injection (SQLi/XSS/Input)",
            "level": _owasp_level_from_score(inj_total_score),
            "signals": inj_all_signals or ["No strong injection/XSS-style indicators from current scan."],
        }
    )

    # A05 – Security Misconfiguration
    mapping.append(
        {
            "id": "A05",
            "name": "Security Misconfiguration",
            "level": _owasp_level_from_score(miscfg_score),
            "signals": miscfg_signals or ["No clear misconfiguration indicators beyond generic web exposure."],
        }
    )

    # A07 – Identification & Authentication Failures
    mapping.append(
        {
            "id": "A07",
            "name": "Identification & Authentication Failures",
            "level": _owasp_level_from_score(auth_score),
            "signals": auth_signals or ["Only limited authentication surface visible in current scan output."],
        }
    )

    return mapping


# =========================
# EXPLAINER – TOOL OUTPUT (LLM / DEMO)
# =========================

def explain_tool_output(tool_label: str, output: str, backend: str) -> str:
    """
    Har tool ka raw output beginner-friendly Hinglish me explain karne ka helper.
    Demo mode me generic guidance, local backend me LLM se real summary.
    """
    name = tool_label.lower()
    if not output or not output.strip():
        return f"{tool_label} ka output empty / unavailable hai, explain karne layak kuch nahi mila."

    # Demo mode: handcrafted short explanation
    if backend.startswith("Demo"):
        if "nmap" in name:
            return (
                "🧑‍🏫 **Nmap Explanation (Demo)**\n\n"
                "- Nmap network scanner hai, jo open ports & services dikhata hai.\n"
                "- Output me `PORT STATE SERVICE` wali lines dekh – yahi main info hai.\n"
                "- `open` wale ports tumhara exposed attack surface hote hain.\n"
                "- Inhi ports pe aage service-specific testing (HTTP, SSH, DB, etc.) hoti hai.\n"
            )
        if "subfinder" in name:
            return (
                "🧑‍🏫 **Subfinder Explanation (Demo)**\n\n"
                "- Subfinder subdomains dhoondta hai (jaise api.example.com, dev.example.com).\n"
                "- Zyada subdomains = zyada attack surface.\n"
                "- Dev/staging/admin type subdomains pe misconfig & weak auth chances zyada hote hain.\n"
            )
        if "httpx" in name:
            return (
                "🧑‍🏫 **httpx Explanation (Demo)**\n\n"
                "- httpx live HTTP hosts, status codes, titles & tech stack show karta hai.\n"
                "- Isse pata chalta hai kaun si host up hai, aur kaunsi tech (e.g. nginx, Apache, React) use ho rahi hai.\n"
            )
        if "nuclei" in name:
            return (
                "🧑‍🏫 **Nuclei Explanation (Demo)**\n\n"
                "- Nuclei template-based scanner hai, jo known misconfigs & CVEs detect karta hai.\n"
                "- Output me `severity:` ya template IDs ko note karo – critical/high pe focus karo.\n"
            )
        if "sqlmap" in name:
            return (
                "🧑‍🏫 **SQLMap Explanation (Demo)**\n\n"
                "- SQLMap SQL injection detection/automation tool hai.\n"
                "- Agar output me injectable params ya union query mention ho, to woh potential SQLi signal hai.\n"
                "- Ye sirf signal hai – hamesha manual verify karo & scope ka respect karo.\n"
            )
        if "xsstrike" in name:
            return (
                "🧑‍🏫 **XSStrike Explanation (Demo)**\n\n"
                "- XSStrike XSS oriented scanner hai.\n"
                "- Output me reflected params, contexts & payloads jo mention hote hain, woh XSS surface show karte hain.\n"
            )
        if "nikto" in name:
            return (
                "🧑‍🏫 **Nikto Explanation (Demo)**\n\n"
                "- Nikto web server misconfigurations & outdated components detect karta hai.\n"
                "- Directory indexing, dangerous HTTP methods, info leak jaise cheezein yaha highlight hoti hain.\n"
            )
        return (
            f"🧑‍🏫 **{tool_label} Explanation (Demo)**\n\n"
            "- Ye tool ka raw output tumhare scan ka technical detail hai.\n"
            "- Demo mode me main generic guidance de raha hoon – real local LLM connect karoge to yahi output line-by-line interpret karwa sakte ho.\n"
        )

    # Local LLM mode – real summarisation
    prompt = dedent(
        f"""
        You are a cybersecurity trainer explaining {tool_label} output.

        - Audience: beginner-friendly but technical (junior security tester).
        - Style: short bullet points, Hinglish allowed (English + a bit of Hindi).
        - Do NOT give exploit payloads or illegal instructions.

        Task:
        - 1) Briefly describe what {tool_label} generally does.
        - 2) Highlight 3–5 interesting patterns/lines from this exact output.
        - 3) Suggest what the tester should look at next, at a high level.

        Raw output (truncated if very long):
        {output[:4000]}
        """
    )
    return call_local_llm(prompt, backend=backend)


# =========================
# EXPLOIT-STYLE TESTING HINTS
# =========================

def generate_exploit_hints(
    surface: Dict[str, Any],
    tool_results: Dict[str, str],
    risk_info: Dict[str, Any],
    ports: List[Dict[str, Any]],
    subdomains: List[str],
    auto_pipeline: Optional[dict],
) -> List[str]:
    hints: List[str] = []

    port_numbers = {p["port"] for p in ports}

    if 80 in port_numbers or 443 in port_numbers:
        hints.append(
            "Web services detected (80/443): auth bypass, IDOR, XSS, SQLi, file upload, rate limiting aur session bugs pe focus karo."
        )

    if 22 in port_numbers:
        hints.append(
            "SSH (22) open hai: weak credentials, key management aur outdated SSH configs ko review kar sakte ho (sirf authorised brute-force)."
        )

    if 21 in port_numbers:
        hints.append(
            "FTP (21) open hai: anonymous login, cleartext creds aur old FTP banner-based vulns ka assessment useful hoga."
        )

    if 3306 in port_numbers or 5432 in port_numbers:
        hints.append(
            "Database ports exposed (3306/5432 etc.): network-level exposure, weak auth aur default creds check karo (scope ke andar hi)."
        )

    if len(subdomains) >= 3:
        hints.append(
            f"{len(subdomains)} subdomains mile: staging/dev/admin type hosts pe misconfigurations aur forgotten panels search karna high value ho sakta hai."
        )

    nuclei_out = tool_results.get("nuclei", "") or ""
    if nuclei_out and "[!]" not in nuclei_out:
        hints.append(
            "Nuclei output ko review karo – headers, misconfig aur known CVEs par high-level manual verification karo (specially critical/high)."
        )

    if auto_pipeline:
        total_urls = len(auto_pipeline.get("paramspider_urls", []))
        if total_urls > 0:
            hints.append(
                f"ParamSpider ne {total_urls} parameterised URLs diye: input validation, reflected/DOM XSS, open redirects aur SQLi ke liye focused testing karo."
            )

    nikto_out = tool_results.get("nikto", "") or ""
    if nikto_out and "[!]" not in nikto_out:
        hints.append(
            "Nikto findings se outdated software, dangerous HTTP methods aur directory indexing jaise low-hanging fruits pe dhyaan do."
        )

    if risk_info.get("label") == "High":
        hints.append(
            "Overall risk High aa raha hai: attack chaining socho (e.g. low severity misconfigs + weak auth = bigger impact path)."
        )

    if not hints:
        hints.append(
            "Current data limited hai – zyada tools enable karke (Nmap full, Nuclei, ParamSpider) fir se scan chalao for richer exploit-style planning hints."
        )

    return hints


# =========================
# TIMELINE & VISUAL MAP
# =========================

def build_timeline_steps(
    use_nmap: bool,
    use_subfinder: bool,
    use_httpx: bool,
    use_nuclei: bool,
    use_ffuf: bool,
    use_dirsearch: bool,
    use_paramspider: bool,
    use_xsstrike: bool,
    use_sqlmap: bool,
    use_nikto: bool,
    use_whois: bool,
    use_traceroute: bool,
    use_curl: bool,
) -> List[Dict[str, str]]:
    steps: List[Dict[str, str]] = []

    steps.append(
        {
            "title": "Initial Recon",
            "desc": "Basic DNS (nslookup) + reachability (ping) check.",
        }
    )

    if use_whois:
        steps.append(
            {
                "title": "WHOIS & Ownership Intel",
                "desc": "Registrar, contacts, nameservers ka high-level view.",
            }
        )

    if use_nmap:
        steps.append(
            {
                "title": "Port & Service Scan (Nmap)",
                "desc": "Open ports, banners aur exposed services identify karna.",
            }
        )

    if use_subfinder:
        steps.append(
            {
                "title": "Subdomain Enumeration (Subfinder)",
                "desc": "Attack surface ko broader internet-facing hosts tak expand karna.",
            }
        )

    if use_httpx:
        steps.append(
            {
                "title": "HTTP Probing (httpx)",
                "desc": "Live hosts, status codes, titles aur tech stack identify karna.",
            }
        )

    if use_nuclei:
        steps.append(
            {
                "title": "Template-Based Scanning (Nuclei)",
                "desc": "Known misconfigs, exposures aur CVE-based issues detect karne ki koshish.",
            }
        )

    if use_paramspider:
        steps.append(
            {
                "title": "ParamSpider → SQLMap → XSStrike Pipeline",
                "desc": "Parameterised URLs collect karke unpe SQLi & XSS detection oriented scanning.",
            }
        )
    else:
        if use_sqlmap:
            steps.append(
                {
                    "title": "Targeted SQLi Testing (SQLMap)",
                    "desc": "Specific parameterised URL pe detection-mode SQL injection checks.",
                }
            )
        if use_xsstrike:
            steps.append(
                {
                    "title": "Targeted XSS Testing (XSStrike)",
                    "desc": "Crawl + fuzzing se XSS possibilities explore karna.",
                }
            )

    if use_ffuf or use_dirsearch:
        steps.append(
            {
                "title": "Content Discovery (FFUF / Dirsearch)",
                "desc": "Hidden directories, panels aur files discover karna.",
            }
        )

    if use_nikto:
        steps.append(
            {
                "title": "Web Server Misconfig Review (Nikto)",
                "desc": "Common misconfigs, info leaks aur outdated components identify karna.",
            }
        )

    if use_traceroute:
        steps.append(
            {
                "title": "Network Path Mapping (Traceroute)",
                "desc": "Client se target tak ka network hop-by-hop path samajhna.",
            }
        )

    if use_curl:
        steps.append(
            {
                "title": "Header Fingerprinting (cURL)",
                "desc": "Security headers, server banner aur caching behaviour check karna.",
            }
        )

    return steps


def build_visual_map_dot(
    target_domain: str,
    surface: Dict[str, Any],
    ports: List[Dict[str, Any]],
    subdomains: List[str],
) -> str:
    ip = surface.get("ip") or target_domain
    dot_lines = [
        "digraph G {",
        '  rankdir=LR;',
        '  node [shape=box style="rounded,filled" fontsize=10 fontname="Consolas"];',
        '  "Internet" [shape=ellipse, fillcolor="#111827", fontcolor="#e5e7eb"];',
        f'  "{target_domain}" [fillcolor="#1d4ed8", fontcolor="#e5e7eb"];',
    ]

    if surface.get("ip"):
        dot_lines.append(
            f'  "{target_domain}" -> "{surface["ip"]}" [label="A record"];'
        )

    for sub in subdomains:
        dot_lines.append(
            f'  "{sub}" [fillcolor="#0f766e", fontcolor="#e5e7eb"];'
        )
        dot_lines.append(
            f'  "{sub}" -> "{target_domain}" [label="subdomain"];'
        )

    for p in ports:
        port_label = f'Port {p["port"]}/{p["service"]}'
        dot_lines.append(
            f'  "{port_label}" [fillcolor="#4b5563", fontcolor="#f9fafb"];'
        )
        dot_lines.append(
            f'  "{ip}" -> "{port_label}" [label="service"];'
        )

    dot_lines.append(f'  "Internet" -> "{target_domain}" [label="client view"];')
    dot_lines.append("}")
    return "\n".join(dot_lines)


# =========================
# ATTACK TREE VISUAL (NEW)
# =========================

def build_attack_tree_dot(
    target_domain: str,
    risk_info: Dict[str, Any],
    owasp_mapping: List[Dict[str, Any]],
    ranked_findings: List[Dict[str, Any]],
    ports: List[Dict[str, Any]],
    auto_pipeline: Optional[dict],
) -> str:
    """
    High-level Attack Tree Visual – colourful, phase-based.
    Root: Target
    Branches: Recon/Surface, Web Layer (OWASP), Network, Params, Hotspots
    """
    score = risk_info.get("score", 0)
    label = risk_info.get("label", "Low")

    if score >= 80:
        root_color = "#b91c1c"  # red
    elif score >= 50:
        root_color = "#ca8a04"  # amber
    else:
        root_color = "#15803d"  # green

    open_ports_count = len(ports)
    param_urls = 0
    if auto_pipeline:
        param_urls = len(auto_pipeline.get("paramspider_urls", []))

    dot = [
        "digraph AttackTree {",
        '  rankdir=TB;',
        '  node [shape=box style="rounded,filled" fontsize=10 fontname="Consolas"];',
    ]

    root_label = f"Target: {target_domain}\\nRisk: {score}/100 ({label})"
    dot.append(
        f'  "root" [label="{root_label}", fillcolor="{root_color}", fontcolor="#f9fafb"];'
    )

    # Phase nodes
    dot.append('  "phase_recon" [label="Recon & Surface", fillcolor="#1d4ed8", fontcolor="#e5e7eb"];')
    dot.append('  "phase_web" [label="Web Layer (OWASP)", fillcolor="#7c3aed", fontcolor="#f9fafb"];')
    dot.append('  "phase_network" [label="Network Exposure", fillcolor="#0f766e", fontcolor="#f9fafb"];')
    dot.append('  "phase_params" [label="Input & Params", fillcolor="#db2777", fontcolor="#fdf2f8"];')
    dot.append('  "phase_hotspots" [label="High Priority Hotspots", fillcolor="#4b5563", fontcolor="#f9fafb"];')

    # Root edges
    dot.append('  "root" -> "phase_recon";')
    dot.append('  "root" -> "phase_web";')
    dot.append('  "root" -> "phase_network";')
    dot.append('  "root" -> "phase_params";')
    dot.append('  "root" -> "phase_hotspots";')

    # Network exposure node
    net_label = f"Approx open ports: {open_ports_count}"
    dot.append(
        f'  "net_ports" [label="{net_label}", fillcolor="#0369a1", fontcolor="#e5e7eb"];'
    )
    dot.append('  "phase_network" -> "net_ports";')

    details = risk_info.get("details", {})
    crit = details.get("nuclei_critical", 0)
    high = details.get("nuclei_high", 0)
    med = details.get("nuclei_medium", 0)
    vuln_sum = f"Critical: {crit} | High: {high} | Medium: {med}"
    dot.append(
        f'  "net_nuclei" [label="Nuclei findings\\n{vuln_sum}", fillcolor="#334155", fontcolor="#e5e7eb"];'
    )
    dot.append('  "phase_network" -> "net_nuclei";')

    # Params / input surface
    param_label = f"Param URLs (ParamSpider): {param_urls}"
    dot.append(
        f'  "params_urls" [label="{param_label}", fillcolor="#be185d", fontcolor="#fdf2f8"];'
    )
    dot.append('  "phase_params" -> "params_urls";')

    # Web layer (OWASP)
    for o in owasp_mapping:
        lvl = o.get("level", "None")
        if lvl == "High":
            c = "#b91c1c"
        elif lvl == "Medium":
            c = "#ca8a04"
        elif lvl == "Low":
            c = "#16a34a"
        else:
            c = "#4b5563"
        node_id = f"owasp_{o['id']}"
        label_text = f"{o['id']} – {o['name']}\\nSignals: {lvl}"
        dot.append(
            f'  "{node_id}" [label="{label_text}", fillcolor="{c}", fontcolor="#f9fafb"];'
        )
        dot.append(f'  "phase_web" -> "{node_id}";')

    # Recon & surface – simple hint nodes
    dot.append(
        '  "recon_dns" [label="DNS, Ping, WHOIS, Traceroute\\n(External view)", fillcolor="#1d4ed8", fontcolor="#e5e7eb"];'
    )
    dot.append('  "phase_recon" -> "recon_dns";')

    # Hotspots from ranked_findings
    if ranked_findings:
        for idx, f in enumerate(ranked_findings[:4], start=1):
            asset = str(f.get("asset") or "")
            if len(asset) > 40:
                asset = asset[:37] + "..."
            prio = f.get("priority", "Low")
            cat = f.get("category", "")
            if prio == "Critical":
                c = "#b91c1c"
            elif prio == "High":
                c = "#c2410c"
            elif prio == "Medium":
                c = "#ca8a04"
            else:
                c = "#4b5563"
            node_id = f"hotspot_{idx}"
            label_text = f"[{prio}] {asset}\\n{cat}"
            dot.append(
                f'  "{node_id}" [label="{label_text}", fillcolor="{c}", fontcolor="#f9fafb"];'
            )
            dot.append(f'  "phase_hotspots" -> "{node_id}";')
    else:
        dot.append(
            '  "hotspot_none" [label="No strong hotspots\\n(current scan config)", fillcolor="#4b5563", fontcolor="#e5e7eb"];'
        )
        dot.append('  "phase_hotspots" -> "hotspot_none";')

    dot.append("}")
    return "\n".join(dot)


# =========================
# THEME CSS (Cyberpunk + Toggle)
# =========================

def apply_theme(theme: str):
    if theme == "Cyber Neon":
        bg_grad = "radial-gradient(circle at top left, #050816 0, #02010a 40%, #000000 100%)"
        card_bg = "rgba(15,23,42,0.92)"
        accent = "#22d3ee"
        accent_soft = "rgba(56,189,248,0.25)"
        text_main = "#f9fafb"
    else:
        bg_grad = "radial-gradient(circle at top left, #0a021f 0, #050017 40%, #02010a 100%)"
        card_bg = "rgba(17,24,39,0.95)"
        accent = "#a855f7"
        accent_soft = "rgba(168,85,247,0.25)"
        text_main = "#e5e7eb"

    st.markdown(
        f"""
        <style>
        [data-testid="stAppViewContainer"] {{
            background: {bg_grad};
            color: {text_main};
        }}
        [data-testid="stHeader"] {{
            background: transparent;
        }}
        .big-title {{
            font-size: 2.4rem;
            font-weight: 900;
            letter-spacing: 0.06em;
            margin-bottom: 0.1rem;
        }}
        .subtitle {{
            font-size: 0.95rem;
            opacity: 0.85;
        }}
        .metric-card {{
            padding: 0.9rem 1.1rem;
            border-radius: 1.1rem;
            background: {card_bg};
            border: 1px solid {accent_soft};
            box-shadow: 0 18px 45px rgba(15,23,42,0.9);
            margin-bottom: 0.5rem;
        }}
        .metric-label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.15em;
            opacity: 0.7;
        }}
        .metric-value {{
            font-size: 1.25rem;
            font-weight: 700;
            margin-top: 0.2rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.7rem;
            border-radius: 999px;
            font-size: 0.75rem;
            border: 1px solid {accent_soft};
            opacity: 0.9;
            margin-right: 0.3rem;
        }}
        .footer {{
            text-align: center;
            font-size: 0.8rem;
            opacity: 0.6;
            margin-top: 2rem;
            padding-top: 0.75rem;
            border-top: 1px solid rgba(148,163,184,0.25);
        }}
        .stTabs [data-baseweb="tab-list"] {{
            gap: 0.35rem;
        }}
        .stTabs [data-baseweb="tab"] {{
            border-radius: 999px;
            padding: 0.25rem 0.9rem;
            background: rgba(15,23,42,0.8);
            border: 1px solid rgba(148,163,184,0.3);
        }}
        .stTabs [data-baseweb="tab"]:hover {{
            border-color: {accent};
        }}
        .timeline-step {{
            border-left: 2px solid {accent_soft};
            padding-left: 0.7rem;
            margin-bottom: 0.6rem;
        }}
        .timeline-title {{
            font-weight: 600;
            font-size: 0.9rem;
        }}
        .timeline-desc {{
            font-size: 0.8rem;
            opacity: 0.85;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


# =========================
# STREAMLIT APP
# =========================

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
)

if "theme" not in st.session_state:
    st.session_state["theme"] = "Cyber Neon"

with st.sidebar:
    st.markdown("## ⚙️ Offensive Control Panel")
    st.write("Use only on **legal & authorised** targets. 👀")

    theme_choice = st.radio(
        "🎨 Theme",
        options=["Cyber Neon", "Dark Purple"],
        index=0 if st.session_state["theme"] == "Cyber Neon" else 1,
    )
    st.session_state["theme"] = theme_choice

    target_domain = st.text_input(
        "🎯 Target Domain",
        value="testphp.vulnweb.com",
        help="Example: example.com"
    )

    # =========================
    # SCAN MODE SELECTOR ✅ (INSIDE SIDEBAR)
    # =========================
    st.markdown("#### 🎯 Scan Mode")

    scan_mode = st.radio(
        "Select Scan Profile",
        options=["Normal", "Bug Bounty Mode", "Learning Mode"],
        index=0,
        help="Normal = default | Bug Bounty = low noise | Learning = explanations"
    )

    st.session_state["scan_mode"] = scan_mode
    # =========================
    # END SCAN MODE
    # =========================

    st.markdown("#### 🔍 Core Tools")
    use_nmap = st.checkbox("Nmap (fast service scan)", value=True)
    use_subfinder = st.checkbox("Subfinder (subdomain enum)", value=True)
    use_httpx = st.checkbox("httpx (probe target)", value=True)
    use_nuclei = st.checkbox("Nuclei (web templates)", value=False)

    st.markdown("#### 🧨 Web Fuzzing / Vuln Scanners")
    use_ffuf = st.checkbox("FFUF (directory fuzz)", value=False)
    use_dirsearch = st.checkbox("Dirsearch (bruteforce dirs)", value=False)
    use_paramspider = st.checkbox(
        "ParamSpider → SQLMap + XSStrike AUTO pipeline",
        value=False,
        help="ParamSpider se URLs nikal ke automatically SQLMap & XSStrike me test karega (safe detection mode).",
    )

    # ✅ NEW: Performance controls for AUTO pipeline
if use_paramspider:
    param_max_urls = st.slider(
        "Max URLs for AUTO pipeline (per scan)",
        min_value=3,
        max_value=25,
        value=8,
        step=1,
        help="Zyada URLs = zyada coverage, par time bhi badhega.",
    )

    param_max_workers = st.slider(
        "Parallel workers (SQLMap + XSStrike)",
        min_value=1,
        max_value=6,
        value=3,
        step=1,
        help="Higher = fast, lekin system pe load bhi zyada.",
    )

# 🔥 YE CHECKBOXES IF KE BAHAR HONGE (IMPORTANT)
use_xsstrike = st.checkbox("XSStrike (manual XSS scanner)", value=False)
use_sqlmap = st.checkbox("SQLMap (manual SQLi check on URL)", value=False)
use_nikto = st.checkbox("Nikto (web server scan)", value=False)

st.markdown("#### 🌐 Network Intel")
use_whois = st.checkbox("WHOIS (ownership / registrar info)", value=False)
use_traceroute = st.checkbox("Traceroute / Tracert", value=False)
use_curl = st.checkbox("cURL headers (quick fingerprint)", value=False)

st.markdown("#### 🧾 Extra Settings")
ffuf_wordlist = st.text_input(
    "FFUF wordlist path",
    value="",
    help="Example: C:/wordlists/common.txt"
)
ffuf_ext = st.text_input(
    "FFUF extensions (comma-separated)",
    value="",
    help="Example: .php,.asp,.aspx"
)
dirsearch_wordlist = st.text_input(
    "Dirsearch wordlist path",
    value="",
    help="Example: C:/wordlists/common.txt"
)
sqlmap_url = st.text_input(
    "SQLMap target URL (manual, with ?param=)",
    value="",
    help="Example: https://site.com/page.php?id=1",
)

run_scan = st.button("🚀 Start Full Recon & AI Attack Path")

if run_scan:

    st.markdown("## 🔎 Scan Results")

    # =========================
    # 🛡️ NIKTO SCAN
    # =========================
    if use_nikto:
        st.markdown("### 🛡️ Nikto Web Server Scan")

        with st.spinner("Running Nikto scan..."):
            nikto_output = run_nikto(target_domain)

        st.code(nikto_output, language="text")

st.markdown("---")
st.markdown("**AI Engine (local)**")

ai_backend = st.radio(
        "LLM backend",
        options=[
            "Demo (built-in)",
            "Local Llama 3.1 8B Q5",
            "Local Qwen 2 7B Q5",
        ],
        index=0,
        help="Jab tumhara local llama-server (http://localhost:8080) chal raha ho, tab Local Llama/Qwen options use karo.",
    )
st.session_state["ai_backend"] = ai_backend

st.caption(
        "If you don't have a local model ready, keep it on 'Demo'.\n"
        "Local mode steps:\n"
        "1) Make sure your GGUF model path is correct\n"
        "2) Run llama-server.exe with that GGUF\n"
        "3) This app will send prompts to http://localhost:8080/v1/chat/completions"
    )

st.markdown("---")
st.markdown("**About this tool**")
st.caption(f"🛡️ {APP_NAME}")
st.caption(f"👨‍💻 Created by **{AUTHOR}**")
st.caption(f"🔖 Version: {VERSION}")

apply_theme(st.session_state["theme"])

st.markdown(
    f"""
    <div class="big-title">🛡️ {APP_NAME}</div>
    <div class="subtitle">
        Enter a domain → run multi-tool recon → get an AI-generated high-level attack path & learning view.<br>
        Focus: <b>offensive mindset for legal security testing & education only.</b><br>
        <b>Created by {AUTHOR}</b>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("")

if not run_scan or not target_domain.strip():
    st.info("👆 Enter a domain on the left, select tools, and click **Start Full Recon & AI Attack Path**.")
else:
    target_domain = target_domain.strip()
    tool_results: Dict[str, str] = {}
    auto_pipeline_results: Optional[dict] = None

    with st.spinner("Running basic recon..."):
        recon = basic_recon(target_domain)

    if use_nmap:
        with st.spinner("Running Nmap scan..."):
            tool_results["nmap"] = run_nmap(target_domain)
    else:
        tool_results["nmap"] = ""

    if use_subfinder:
        with st.spinner("Running Subfinder..."):
            tool_results["subfinder"] = run_subfinder(target_domain)
    else:
        tool_results["subfinder"] = ""

    if use_httpx:
        with st.spinner("Probing target with httpx..."):
            tool_results["httpx"] = run_httpx(target_domain)
    else:
        tool_results["httpx"] = ""

    if use_nuclei:
        with st.spinner("Running Nuclei scan (this may take some time)..."):
            tool_results["nuclei"] = run_nuclei(target_domain)
    else:
        tool_results["nuclei"] = ""

    if use_ffuf:
        with st.spinner("Running FFUF directory fuzzing..."):
            tool_results["ffuf"] = run_ffuf(target_domain, ffuf_wordlist, ffuf_ext)
    else:
        tool_results["ffuf"] = ""

    if use_dirsearch:
        with st.spinner("Running Dirsearch brute forcing..."):
            tool_results["dirsearch"] = run_dirsearch(target_domain, dirsearch_wordlist)
    else:
        tool_results["dirsearch"] = ""

    if use_paramspider:
        with st.spinner("Running ParamSpider → SQLMap → XSStrike auto pipeline (FAST mode)..."):
            auto_pipeline_results = full_auto_pipeline(
                target_domain,
                max_urls=param_max_urls,
                max_workers=param_max_workers,
            )
            urls = auto_pipeline_results.get("paramspider_urls", [])
            tested = auto_pipeline_results.get("tested_urls", [])
            tool_results["paramspider"] = (
                f"[+] ParamSpider collected {len(urls)} URLs with parameters.\n"
                f"[+] Auto pipeline tested {len(tested)} URLs with SQLMap & XSStrike (parallel, detection mode)."
            )
    else:
        tool_results["paramspider"] = ""

    if use_xsstrike and not use_paramspider:
        with st.spinner("Running XSStrike XSS scan (manual mode)..."):
            tool_results["xsstrike"] = run_xsstrike(target_domain)
    else:
        if "xsstrike" not in tool_results:
            tool_results["xsstrike"] = ""

    if use_sqlmap and not use_paramspider:
        with st.spinner("Running SQLMap (manual mode)..."):
            manual_url = sqlmap_url.strip()
            if manual_url:
                url_for_sqlmap = manual_url
            else:
                base = build_url(target_domain)
                base = base.rstrip("/")
                url_for_sqlmap = f"{base}/index.php?id=1"
            tool_results["sqlmap"] = run_sqlmap(url_for_sqlmap)
    else:
        if "sqlmap" not in tool_results:
            tool_results["sqlmap"] = ""

    if use_nikto:
        with st.spinner("Running Nikto web server scan..."):
            tool_results["nikto"] = run_nikto(target_domain)
    else:
        tool_results["nikto"] = ""

    if use_whois:
        with st.spinner("Fetching WHOIS info..."):
            tool_results["whois"] = run_whois(target_domain)
    else:
        tool_results["whois"] = ""

    if use_traceroute:
        with st.spinner("Running Traceroute / Tracert..."):
            tool_results["traceroute"] = run_traceroute(target_domain)
    else:
        tool_results["traceroute"] = ""

    if use_curl:
        with st.spinner("Fetching HTTP headers with cURL..."):
            tool_results["curl_headers"] = run_curl_headers(target_domain)
    else:
        tool_results["curl_headers"] = ""

    with st.spinner("Analysing attack surface with AI, OWASP mapping & scoring..."):
        surface = build_attack_surface_summary(recon, tool_results)
        risk_info = estimate_risk(surface, tool_results)

        ports = parse_nmap_open_ports(tool_results.get("nmap", ""))
        subdomains = parse_subfinder_output(tool_results.get("subfinder", ""), target_domain)

        correlated_findings = correlate_vulnerabilities(
            target_domain=target_domain,
            tool_results=tool_results,
            auto_pipeline=auto_pipeline_results,
            ports=ports,
            subdomains=subdomains,
        )
        ranked_findings = rank_findings(correlated_findings, risk_info)

        # OWASP mapping
        owasp_mapping = build_owasp_mapping(
            target_domain=target_domain,
            tool_results=tool_results,
            correlated_findings=correlated_findings,
            auto_pipeline=auto_pipeline_results,
        )

        llm_prompt = attack_surface_to_prompt(surface, tool_results, auto_pipeline=auto_pipeline_results)
        backend = st.session_state.get("ai_backend", "Demo (built-in)")
        ai_attack_plan = call_local_llm(llm_prompt, backend=backend)

        ai_ranking_comment = build_ai_ranking_comment(ranked_findings, risk_info, backend=backend)

        scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Risk trend history (session-based)
    if "risk_history" not in st.session_state:
        st.session_state["risk_history"] = []
    st.session_state["risk_history"].append(
        {
            "time": scan_time,
            "score": risk_info["score"],
            "label": risk_info["label"],
            "domain": target_domain,
        }
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Target</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{target_domain}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Resolved IP</div>', unsafe_allow_html=True)
        ip_text = surface.get("ip") or "N/A"
        st.markdown(f'<div class="metric-value">{ip_text}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Scan Time (UTC)</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{scan_time}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Risk Score</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div class="metric-value">{risk_info["score"]}/100 ({risk_info["label"]})</div>',
            unsafe_allow_html=True,
        )
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown(
        """
        <div style="margin: 0.4rem 0 0.8rem 0;">
            <span class="badge">AI-Assist Mode</span>
            <span class="badge">Multi-Tool Orchestration</span>
            <span class="badge">Risk Estimate (Educational)</span>
            <span class="badge">ParamSpider → SQLMap → XSStrike Pipeline (FAST)</span>
            <span class="badge">Vulnerability Correlation</span>
            <span class="badge">OWASP Top 10 Mapping (Approx)</span>
            <span class="badge">Risk Trend (Session)</span>
            <span class="badge">Attack Tree Visual</span>
            <span class="badge">HTTP/HTTPS Auto</span>
            <span class="badge">Created by Dip Kar</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["📍 Attack Surface", "🧠 AI Attack Path & Ranking", "📄 Raw Recon", "🛠️ Tool Outputs", "📝 Report & Export"]
    )

    # TAB 1
    with tab1:
        st.subheader("📍 Attack Surface Overview")
        st.write(
            "Ye section external view deta hai (DNS, reachability, host-level info aur kuch visualisations)."
        )
        st.markdown("**Primary Host**")
        st.write(f"- Domain: `{surface.get('domain')}`")
        st.write(f"- IP: `{surface.get('ip') or 'N/A'}`")
        st.write(
            f"- Rough Risk Score: **{risk_info['score']}/100 – {risk_info['label']}** "
            "(visual estimate only, not a formal rating)."
        )

        if surface.get("assets"):
            st.markdown("**Detected Assets (high-level)**")
            for a in surface["assets"]:
                st.write(
                    f"- **[{a.get('risk','').upper()}] {a.get('type').title()}** — {a.get('label')}  \n"
                    f"  _Reason:_ {a.get('reason')}"
                )
        if surface.get("notes"):
            st.markdown("**Notes**")
            for n in surface["notes"]:
                st.write(f"- {n}")

        if auto_pipeline_results:
            st.markdown("---")
            st.markdown("**ParamSpider / SQLMap / XSStrike Overview (auto mode)**")
            total_urls = len(auto_pipeline_results.get("paramspider_urls", []))
            tested_urls = len(auto_pipeline_results.get("tested_urls", []))
            st.write(f"- ParamSpider parameterised URLs: **{total_urls}**")
            st.write(f"- URLs tested with SQLMap & XSStrike: **{tested_urls}** (auto pipeline, parallel)")

        st.markdown("---")
        st.markdown("### 📊 Visual Graphs")

        col_g1, col_g2 = st.columns(2)

        with col_g1:
            st.markdown("**Open Ports Overview (from Nmap)**")
            if ports:
                df_ports = pd.DataFrame(ports).sort_values("port")
                chart_ports = (
                    alt.Chart(df_ports)
                    .mark_bar()
                    .encode(
                        x=alt.X("port:O", title="Port"),
                        y=alt.Y("count():Q", title="Count"),
                        tooltip=["port", "service", "proto"],
                    )
                    .properties(height=260)
                )
                st.altair_chart(chart_ports, use_container_width=True)
            else:
                st.write("Nmap output se koi open ports parse nahi ho paye (ya Nmap run nahi hua).")

        with col_g2:
            st.markdown("**Subdomain Distribution (from Subfinder)**")
            if subdomains:
                df_subs = pd.DataFrame({"subdomain": subdomains})
                chart_subs = (
                    alt.Chart(df_subs)
                    .mark_bar()
                    .encode(
                        x=alt.X("subdomain:N", title="Subdomain"),
                        y=alt.Y("count():Q", title="Count"),
                        tooltip=["subdomain"],
                    )
                    .properties(height=260)
                )
                st.altair_chart(chart_subs, use_container_width=True)
            else:
                st.write("Subfinder output empty hai ya run nahi hua – subdomain graph show nahi ho sakta.")

        st.markdown("#### 🔥 Risk Heatmap (approx)")
        details = risk_info.get("details", {})
        heat_data = [
            {
                "dimension": "Ports & Services",
                "metric": "Open Ports (est.)",
                "value": details.get("open_ports_estimate", 0),
            },
            {"dimension": "Vulnerabilities", "metric": "Critical", "value": details.get("nuclei_critical", 0)},
            {"dimension": "Vulnerabilities", "metric": "High", "value": details.get("nuclei_high", 0)},
            {"dimension": "Vulnerabilities", "metric": "Medium", "value": details.get("nuclei_medium", 0)},
        ]
        df_heat = pd.DataFrame(heat_data)
        heat_chart = (
            alt.Chart(df_heat)
            .mark_rect()
            .encode(
                x=alt.X("metric:N", title="Metric"),
                y=alt.Y("dimension:N", title="Area"),
                color=alt.Color("value:Q", title="Intensity"),
                tooltip=["dimension", "metric", "value"],
            )
            .properties(height=180)
        )
        st.altair_chart(heat_chart, use_container_width=True)

        st.markdown("---")
        st.markdown("### 📈 Risk Trend (This Session)")
        history = st.session_state.get("risk_history", [])
        if history:
            df_hist = pd.DataFrame(history)
            df_domain_hist = df_hist[df_hist["domain"] == target_domain].copy()
            if not df_domain_hist.empty:
                df_domain_hist = df_domain_hist.reset_index(drop=True)
                df_domain_hist["scan_index"] = df_domain_hist.index + 1
                trend_chart = (
                    alt.Chart(df_domain_hist)
                    .mark_line(point=True)
                    .encode(
                        x=alt.X("scan_index:O", title="Scan #"),
                        y=alt.Y("score:Q", title="Risk Score"),
                        tooltip=["scan_index", "score", "time", "label"],
                    )
                    .properties(height=200)
                )
                st.altair_chart(trend_chart, use_container_width=True)
            else:
                st.write("Is domain ke liye abhi sirf ek scan record hai.")
        else:
            st.write("Abhi tak risk history empty hai (ye session me koi previous scan nahi).")

        st.markdown("---")
        st.markdown("### 🧱 OWASP Top 10 Coverage (Approx – Signal Based)")
        st.write(
            "Ye mapping sirf tools ke signals pe based rough view hai. Exact manual testing / validation zaroori hai."
        )
        if owasp_mapping:
            df_owasp = pd.DataFrame(
                [
                    {
                        "OWASP ID": c["id"],
                        "Category": c["name"],
                        "Signal Level": c["level"],
                        "Key Signals": "; ".join(c["signals"][:3]),
                    }
                    for c in owasp_mapping
                ]
            )
            st.dataframe(df_owasp, use_container_width=True)
        else:
            st.write("OWASP mapping ke liye abhi kaafi signals available nahi hain.")

        st.markdown("---")
        st.markdown("### ⏱️ Timeline View (Recon → Attack Path Planning)")

        timeline_steps = build_timeline_steps(
            use_nmap=use_nmap,
            use_subfinder=use_subfinder,
            use_httpx=use_httpx,
            use_nuclei=use_nuclei,
            use_ffuf=use_ffuf,
            use_dirsearch=use_dirsearch,
            use_paramspider=use_paramspider,
            use_xsstrike=use_xsstrike,
            use_sqlmap=use_sqlmap,
            use_nikto=use_nikto,
            use_whois=use_whois,
            use_traceroute=use_traceroute,
            use_curl=use_curl,
        )

        if timeline_steps:
            for idx, step in enumerate(timeline_steps, start=1):
                st.markdown(
                    f"""
                    <div class="timeline-step">
                        <div class="timeline-title">{idx}. {step['title']}</div>
                        <div class="timeline-desc">{step['desc']}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.write("Timeline khali hai, kyunki sirf basic recon run hua.")

        st.markdown("---")
        st.markdown("### 🗺️ Visual Attack Surface Map")
        try:
            dot = build_visual_map_dot(target_domain, surface, ports, subdomains)
            st.graphviz_chart(dot)
        except Exception as e:
            st.write(f"Graphviz visual map render nahi ho paya: {e}")

        st.markdown("---")
        st.info(
            "Ye sab visualisations sirf starting point hai. Tum chaho to Nmap/httpx/nuclei output parse karke "
            "aur advanced graphs bana sakte ho."
        )

    # TAB 2
    with tab2:
        st.subheader("🧠 AI-Generated Attack Path (High-Level, Educational)")
        st.write(
            "Niche diya gaya flow sirf **educational & planning** ke liye hai – koi exploit code ya illegal details nahi."
        )
        st.markdown("---")
        st.markdown(ai_attack_plan)
        st.markdown("---")

        st.markdown("### 🌳 Attack Tree Visual (High-Level View)")
        st.write(
            "Ye tree tumhe phases ke hisaab se dikhata hai: Recon → Web Layer (OWASP) → Network → Params → High-priority hotspots."
        )
        try:
            tree_dot = build_attack_tree_dot(
                target_domain=target_domain,
                risk_info=risk_info,
                owasp_mapping=owasp_mapping,
                ranked_findings=ranked_findings,
                ports=ports,
                auto_pipeline=auto_pipeline_results,
            )
            st.graphviz_chart(tree_dot)
        except Exception as e:
            st.write(f"Attack tree render nahi ho paya: {e}")

        st.markdown("### 🎯 Correlated Vulnerability Hotspots (Local Scoring)")
        if ranked_findings:
            df_ranked = pd.DataFrame(
                [
                    {
                        "Asset": f["asset"],
                        "Category": f["category"],
                        "Priority": f["priority"],
                        "Score (0-10)": f["score"],
                    }
                    for f in ranked_findings
                ]
            )
            st.dataframe(df_ranked.head(10), use_container_width=True)
        else:
            st.write("Filhaal koi strong correlated hotspot detect nahi hua.")

        st.markdown("### 🤖 AI Ranking Comment (Short View)")
        st.markdown(ai_ranking_comment)

        st.markdown("### 💡 Exploit-Led Testing Hints (High-Level Only)")
        hints = generate_exploit_hints(
            surface=surface,
            tool_results=tool_results,
            risk_info=risk_info,
            ports=ports,
            subdomains=subdomains,
            auto_pipeline=auto_pipeline_results,
        )
        for h in hints:
            st.write(f"- {h}")

    # TAB 3
    with tab3:
        st.subheader("📄 Raw Recon Data (Core)")
        st.markdown("**Basic recon JSON**")
        st.code(json.dumps(recon, indent=2), language="json")

        st.markdown("**AI Prompt (for debugging / tuning)**")
        st.code(llm_prompt, language="text")

        st.markdown("**Risk Details (debug view)**")
        st.code(json.dumps(risk_info, indent=2), language="json")

        st.markdown("**Correlated Findings (debug)**")
        st.code(json.dumps(correlated_findings, indent=2), language="json")

        st.markdown("**OWASP Mapping (debug)**")
        st.code(json.dumps(owasp_mapping, indent=2), language="json")

        if auto_pipeline_results:
            st.markdown("**Auto Pipeline Meta (debug view)**")
            st.code(json.dumps(auto_pipeline_results, indent=2)[:6000], language="json")

    # TAB 4
    with tab4:
        st.subheader("🛠️ Individual Tool Outputs")
        st.write("Raw outputs of the tools you selected are shown here. Neeche 'Explain' button se samjha bhi sakte ho.")

        backend = st.session_state.get("ai_backend", "Demo (built-in)")

        for name, output in tool_results.items():
            if not output:
                continue
            nice_name = name.replace("_", " ")
            with st.expander(f"🔹 {nice_name} output", expanded=False):
                st.code(output, language="bash")
                if st.button(f"🤖 Explain {nice_name}", key=f"explain_{name}"):
                    explanation = explain_tool_output(nice_name, output, backend=backend)
                    st.markdown(explanation)

        if auto_pipeline_results:
            st.markdown("---")
            st.subheader("🔥 Auto ParamSpider → SQLMap → XSStrike Results")

            urls = auto_pipeline_results.get("paramspider_urls", [])
            tested_urls = auto_pipeline_results.get("tested_urls", [])

            with st.expander("ParamSpider URLs (cleaned + with params)", expanded=False):
                if urls:
                    st.code("\n".join(urls[:200]), language="text")
                    if len(urls) > 200:
                        st.text(f"... and {len(urls) - 200} more")
                else:
                    st.write("No URLs found by ParamSpider.")

            st.subheader("SQLMap Detection Results")
            for u, res in auto_pipeline_results.get("sqlmap", {}).items():
                with st.expander(f"SQLMap → {u}", expanded=False):
                    st.code(res, language="bash")
                    if st.button(f"🤖 Explain SQLMap for {u}", key=f"explain_sqlmap_{u}"):
                        explanation = explain_tool_output("SQLMap", res, backend=backend)
                        st.markdown(explanation)

            st.subheader("XSStrike XSS Results")
            for u, res in auto_pipeline_results.get("xsstrike", {}).items():
                with st.expander(f"XSStrike → {u}", expanded=False):
                    st.code(res, language="bash")
                    if st.button(f"🤖 Explain XSStrike for {u}", key=f"explain_xsstrike_{u}"):
                        explanation = explain_tool_output("XSStrike", res, backend=backend)
                        st.markdown(explanation)

        if not any(v for v in tool_results.values()) and not auto_pipeline_results:
            st.info("No extra tools were run. Select tools from the sidebar and run the scan again.")

    # TAB 5
    with tab5:
        st.subheader("📝 Report (Auto-Generated) & Export")
        st.write(
            "Ye basic report skeleton hai – tum ise client / internal report / notes ke template ki tarah customise kar sakte ho."
        )

        report_md = f"""
        # Offensive Recon & AI Attack Path Report

        - **Target Domain:** `{surface.get('domain')}`
        - **Resolved IP:** `{surface.get('ip') or 'N/A'}`
        - **Scan Time (UTC):** {scan_time}
        - **Overall Risk (rough visual estimate):** {risk_info['score']}/100 – {risk_info['label']}
        - **Generated By:** {APP_NAME} (Created by {AUTHOR})

        ---

        ## 1. High-Level Summary

        Ye report basic recon + selected tools + AI se derived high-level attack path show karti hai.
        Purpose: **legal security testing, learning & planning** only.

        ---

        ## 2. Observed Attack Surface

        - Domain: `{surface.get('domain')}`
        - IP: `{surface.get('ip') or 'N/A'}`

        ### Notes:
        """

        for n in surface.get("notes", []):
            report_md += f"- {n}\n"

        if auto_pipeline_results:
            total_urls = len(auto_pipeline_results.get("paramspider_urls", []))
            tested_urls = len(auto_pipeline_results.get("tested_urls", []))
            report_md += f"\n- ParamSpider parameterised URLs: **{total_urls}**\n"
            report_md += f"- URLs tested with SQLMap & XSStrike (auto pipeline): **{tested_urls}**\n"

        report_md += """

        ---

        ## 3. Tools Executed

        """

        for t in surface.get("tools_ran", []):
            report_md += f"- {t}\n"

        report_md += """

        ---

        ## 4. Correlated Vulnerability Hotspots & Priority

        Ye section local scoring + correlation pe based hai (AI-style ranking, but exploit-less).

        """

        if ranked_findings:
            for f in ranked_findings[:10]:
                report_md += (
                    f"- **[{f['priority']}] {f['asset']}** "
                    f"(Category: {f['category']}, Score: {f['score']}/10)\n"
                )
        else:
            report_md += "- No strong hotspots identified with current scan configuration.\n"

        report_md += """

        ---

        ## 4.1 OWASP Top 10 Coverage (Approx – Signal Based)

        Ye mapping tools ke outputs se derived high-level signal hai.
        Manual verification & detailed testing hamesha zaroori hai.

        """

        for cat in owasp_mapping:
            signals_preview = ", ".join(cat["signals"][:3]) if cat.get("signals") else "No clear signals."
            report_md += (
                f"- **{cat['id']} – {cat['name']}**: {cat['level']} signals  \n"
                f"  _Signals:_ {signals_preview}\n"
            )

        report_md += """

        ---

        ## 5. AI Attack Path (High-Level Idea)

        Niche diya gaya attack flow sirf **thinking framework** hai.
        Real-world testing me hamesha defined **scope, permissions & legal boundaries** follow karo.

        """

        report_md += "\n\n---\n\n```text\n" + ai_attack_plan + "\n```"

        st.markdown(report_md)

        export_bundle = {
            "meta": {
                "app_name": APP_NAME,
                "author": AUTHOR,
                "version": VERSION,
                "scan_time_utc": scan_time,
                "target_domain": surface.get("domain"),
                "ip": surface.get("ip"),
            },
            "risk": risk_info,
            "recon": recon,
            "surface": surface,
            "tool_results": tool_results,
            "ai_attack_plan": ai_attack_plan,
            "ai_prompt": llm_prompt,
            "auto_pipeline": auto_pipeline_results,
            "correlated_findings": correlated_findings,
            "ranked_findings": ranked_findings,
            "ai_ranking_comment": ai_ranking_comment,
            "owasp_mapping": owasp_mapping,
            "risk_history": st.session_state.get("risk_history", []),
        }

        json_str = json.dumps(export_bundle, indent=2)
        safe_domain = (surface.get("domain") or "target").replace(".", "_")
        ts_slug = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        md_filename = f"Offensive_report_{safe_domain}_{ts_slug}.md"
        json_filename = f"Offensive_bundle_{safe_domain}_{ts_slug}.json"

        st.markdown("---")
        st.subheader("⬇️ Export")
        st.download_button(
            "Download Markdown Report",
            report_md,
            file_name=md_filename,
            mime="text/markdown",
        )
        st.download_button(
            "Download JSON Scan Bundle",
            json_str,
            file_name=json_filename,
            mime="application/json",
        )

    st.markdown(
        f"""
        <div class="footer">
            Built for learning, legal red teaming & offensive mindset practice only. <br>
            🛡️ {APP_NAME} • 👨‍💻 Created by <b>{AUTHOR}</b> • 🔖 {VERSION}
        </div>
        """,
        unsafe_allow_html=True,
    )
