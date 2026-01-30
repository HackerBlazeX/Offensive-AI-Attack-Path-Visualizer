import subprocess
import shutil
import streamlit as st

# =========================
# TOOL DEFINITIONS
# =========================

CORE_TOOLS = {
    "nmap": "nmap",
    "subfinder": "subfinder",
    "httpx": "httpx",
    "nuclei": "nuclei",
    "git": "git",
}

OPTIONAL_TOOLS = {
    "ffuf": "ffuf",
    "paramspider": "paramspider",
    "sqlmap": "sqlmap",
    "xsstrike": "xsstrike",
    "nikto": "nikto",
}

# =========================
# CHECK TOOL EXISTS
# =========================

def is_tool_installed(tool: str) -> bool:
    return shutil.which(tool) is not None


# =========================
# INSTALL TOOL (Chocolatey)
# =========================

def install_tool(tool: str) -> str:
    try:
        cmd = ["choco", "install", tool, "-y"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"[!] Install failed: {e}"


# =========================
# MAIN INSTALL CHECKER
# =========================

def check_and_prompt_install(core=True, optional=True):
    missing = []

    if core:
        for tool in CORE_TOOLS:
            if not is_tool_installed(tool):
                missing.append(tool)

    if optional:
        for tool in OPTIONAL_TOOLS:
            if not is_tool_installed(tool):
                missing.append(tool)

    if not missing:
        st.success("✅ All required tools are already installed.")
        return

    st.warning(f"⚠️ Missing tools detected: {', '.join(missing)}")

    if st.button("📦 Install missing tools now (Chocolatey required)"):
        for tool in missing:
            with st.spinner(f"Installing {tool}..."):
                output = install_tool(tool)
                st.code(output, language="bash")

        st.success("✅ Installation process finished. Restart scan if needed.")
