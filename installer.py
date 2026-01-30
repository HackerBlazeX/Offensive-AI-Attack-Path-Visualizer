import subprocess
import shutil
import streamlit as st
import platform

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
# ENVIRONMENT CHECKS
# =========================

def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_choco_installed() -> bool:
    return shutil.which("choco") is not None


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
        return result.stdout + "\n" + result.stderr
    except Exception as e:
        return f"[!] Install failed for {tool}: {e}"


# =========================
# MAIN INSTALLER UI
# =========================

def check_and_prompt_install(core=True, optional=True):

    st.markdown("## 🧰 Dependency Installer")

    # OS CHECK
    if not is_windows():
        st.error("❌ Auto installer currently supports **Windows only**.")
        st.info("👉 On Linux/macOS, please install tools manually.")
        return

    # CHOCOLATEY CHECK
    if not is_choco_installed():
        st.error("❌ Chocolatey is not installed.")
        st.markdown(
            "👉 Install Chocolatey first from: "
            "[https://chocolatey.org/install](https://chocolatey.org/install)"
        )
        return

    # CHECK MISSING TOOLS
    missing_core = []
    missing_optional = []

    if core:
        for tool in CORE_TOOLS:
            if not is_tool_installed(tool):
                missing_core.append(tool)

    if optional:
        for tool in OPTIONAL_TOOLS:
            if not is_tool_installed(tool):
                missing_optional.append(tool)

    if not missing_core and not missing_optional:
        st.success("✅ All required tools are already installed.")
        return

    # SHOW STATUS
    if missing_core:
        st.warning(f"⚠️ Missing CORE tools: {', '.join(missing_core)}")

    if missing_optional:
        st.info(f"ℹ️ Missing OPTIONAL tools: {', '.join(missing_optional)}")

    st.markdown("---")

    # INSTALL BUTTONS
    col1, col2 = st.columns(2)

    with col1:
        install_core = st.button("📦 Install CORE tools")

    with col2:
        install_optional = st.button("🧪 Install OPTIONAL tools")

    # INSTALL CORE
    if install_core and missing_core:
        for tool in missing_core:
            with st.spinner(f"Installing {tool}..."):
                output = install_tool(tool)
                st.code(output, language="bash")
        st.success("✅ CORE tools installation finished.")
        st.info("🔁 Restart the app if any tool was newly installed.")

    # INSTALL OPTIONAL
    if install_optional and missing_optional:
        for tool in missing_optional:
            with st.spinner(f"Installing {tool}..."):
                output = install_tool(tool)
                st.code(output, language="bash")
        st.success("✅ OPTIONAL tools installation finished.")
        st.info("🔁 Restart the app if any tool was newly installed.")
