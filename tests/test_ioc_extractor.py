from exe_triage.analyzers.ioc_extractor import extract


def test_extract_urls():
    strings = ["Connect to http://malware.example.com/download now", "another string"]
    result = extract(strings)
    assert len(result.urls) == 1
    assert "http://malware.example.com/download" in result.urls[0]


def test_extract_ips():
    strings = ["Connecting to 8.8.8.8 for DNS", "Server: 1.2.3.4"]
    result = extract(strings)
    assert "8.8.8.8" in result.ips
    assert "1.2.3.4" in result.ips


def test_filters_private_ips():
    strings = ["gateway: 192.168.1.1", "loopback: 127.0.0.1"]
    result = extract(strings)
    assert "192.168.1.1" not in result.ips
    assert "127.0.0.1" not in result.ips


def test_extract_file_paths():
    strings = ["%AppData%\\update.exe", "%Temp%\\~tmp.bat"]
    result = extract(strings)
    assert len(result.file_paths) == 2


def test_extract_registry_keys():
    strings = ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\myapp"]
    result = extract(strings)
    assert len(result.registry_keys) >= 1


def test_extract_process_names():
    strings = ["Spawning powershell.exe process", "cmd.exe /c whoami"]
    result = extract(strings)
    assert "powershell.exe" in result.process_names
    assert "cmd.exe" in result.process_names


def test_no_iocs_in_clean_strings():
    strings = ["Hello world", "This is a test", "Normal string here"]
    result = extract(strings)
    assert result.urls == []
    assert result.ips == []
