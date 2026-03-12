import re

from exe_triage.models import IOCResult

# Regex patterns
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]{8,}", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|info|biz|xyz|tk|top|cc|tv|me)\b",
    re.IGNORECASE,
)
REGISTRY_PATTERN = re.compile(
    r"(?:CurrentVersion\\Run(?:Once)?|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?)",
    re.IGNORECASE,
)
PROCESS_NAMES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
    "cscript.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe",
}
WINDOWS_PATH_PATTERN = re.compile(
    r"(?:%AppData%|%Temp%|%TEMP%|%Startup%|%USERPROFILE%|%SystemRoot%|C:\\Windows\\|C:\\Users\\)[^\s\"'<>]{0,100}",
    re.IGNORECASE,
)

# Private/reserved IP ranges to filter (optional)
PRIVATE_IP_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.0.0.0", "255.255.255.255",
)


def _is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def extract(strings: list[str]) -> IOCResult:
    """Extract observable IOCs from strings."""
    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    file_paths: list[str] = []
    registry_keys: list[str] = []
    process_names: list[str] = []

    seen_urls: set[str] = set()
    seen_domains: set[str] = set()
    seen_ips: set[str] = set()
    seen_paths: set[str] = set()
    seen_registry: set[str] = set()

    for s in strings:
        s_lower = s.lower()

        # URLs
        for match in URL_PATTERN.finditer(s):
            url = match.group()
            if url not in seen_urls:
                seen_urls.add(url)
                urls.append(url)

        # IPs (excluding private ranges)
        for match in IP_PATTERN.finditer(s):
            ip = match.group()
            if _is_valid_ip(ip) and not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    ips.append(ip)

        # Domains (but not if they look like IPs)
        for match in DOMAIN_PATTERN.finditer(s):
            domain = match.group().lower()
            if domain not in seen_domains and not IP_PATTERN.match(domain):
                seen_domains.add(domain)
                domains.append(domain)

        # Windows paths
        for match in WINDOWS_PATH_PATTERN.finditer(s):
            path = match.group()
            if path not in seen_paths:
                seen_paths.add(path)
                file_paths.append(path)

        # Registry keys
        for match in REGISTRY_PATTERN.finditer(s):
            key = match.group()
            if key not in seen_registry:
                seen_registry.add(key)
                registry_keys.append(key)

        # Process names
        for proc in PROCESS_NAMES:
            if proc in s_lower and proc not in process_names:
                process_names.append(proc)

    return IOCResult(
        urls=urls,
        domains=domains,
        ips=ips,
        file_paths=file_paths,
        registry_keys=registry_keys,
        process_names=process_names,
    )
