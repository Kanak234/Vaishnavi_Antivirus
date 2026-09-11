"""Unit test suite for Vaishnavi Antivirus suite."""

import tempfile
from pathlib import Path

import pytest
from kali_defense import KaliDefense
from lakshmi_guard import LakshmiGuard
from saraswati_shield import SaraswatiShield
from vaishnavi_antivirus_5000_lines import (
    LakshmiGuard as LakshmiSuiteGuard,
)
from vaishnavi_antivirus_5000_lines import (
    SaraswatiShield as SaraswatiSuiteShield,
)
from vaishnavi_av.heuristics import simple_heuristic
from vaishnavi_av.logger import setup_logger
from vaishnavi_av.main import run as cli_run
from vaishnavi_av.quarantine import move_to_quarantine
from vaishnavi_av.scanner import scan_path
from vaishnavi_av.signatures import SAMPLE_SIGNATURES, file_hash, match
from vaishnavi_av.utils import is_text_file


@pytest.fixture
def temp_dir():
    """Create a temporary directory for scanning tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_signatures_eicar(temp_dir):
    """Verify EICAR signature detection."""
    eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_file = temp_dir / "eicar.com"
    eicar_file.write_bytes(eicar_content)

    h = file_hash(eicar_file)
    assert h == SAMPLE_SIGNATURES["eicar-test-file"]
    assert match(eicar_file) is True


def test_signatures_clean_file(temp_dir):
    """Verify benign files are not flagged by signature matcher."""
    clean_file = temp_dir / "clean_notes.txt"
    clean_file.write_text("Hello, this is a legitimate document with no malware.")

    assert match(clean_file) is False


def test_heuristics_suspicious_filename(temp_dir):
    """Verify filename heuristic detects 'malware' and 'virus' keywords."""
    f_mal = temp_dir / "sample_malware_test.bin"
    f_mal.write_text("suspicious content")

    f_vir = temp_dir / "my_virus_installer.sh"
    f_vir.write_text("echo payload")

    f_clean = temp_dir / "report_2026.pdf"
    f_clean.write_text("Q3 Financial Analysis")

    assert simple_heuristic(f_mal) is True
    assert simple_heuristic(f_vir) is True
    assert simple_heuristic(f_clean) is False


def test_heuristics_zero_byte_file(temp_dir):
    """Verify zero-byte files are flagged by heuristics."""
    empty_file = temp_dir / "empty_anomaly.dat"
    empty_file.touch()

    assert simple_heuristic(empty_file) is True


def test_quarantine_move(temp_dir):
    """Verify flagged files can be quarantined successfully."""
    flagged = temp_dir / "bad_file.bin"
    flagged.write_bytes(b"\x00\x01\x02\x03\x04")

    quarantine_dest = move_to_quarantine(flagged)
    assert quarantine_dest is not None
    assert quarantine_dest.exists()
    assert quarantine_dest.name == "bad_file.bin"


def test_scanner_directory(temp_dir):
    """Verify end-to-end scanner finds signature and heuristic threats in a directory."""
    logger = setup_logger("test_dir_scan")
    # 1. Clean file
    (temp_dir / "clean.txt").write_text("All is fine.")

    # 2. EICAR signature match
    (temp_dir / "eicar.com").write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    # 3. Heuristic match
    (temp_dir / "trojan_malware.exe").write_bytes(b"binary data")

    findings = scan_path(temp_dir, logger=logger, max_files=50)
    assert len(findings) == 2

    reasons = {f["reason"] for f in findings}
    assert "signature" in reasons
    assert "heuristic" in reasons



def test_shield_modules():
    """Verify standalone shield classes return proper threat assessment strings."""
    saraswati = SaraswatiShield()
    report = saraswati.intelligent_scan("Memory Block 0x4000")
    assert "Saraswati Shield (AI Intelligence)" in report
    assert "Status: Clean" in report

    kali = KaliDefense()
    elim = kali.destroy_threat("Worm.Win32.Blaster")
    assert "Kali Defense (Threat Neutralization)" in elim
    assert "Action Taken: Eliminated Successfully." in elim

    lakshmi = LakshmiGuard()
    opt = lakshmi.optimize_system()
    assert "Lakshmi Guard (System Stability)" in opt
    assert "System Performance Stable." in opt


def test_suite_shield_and_guard(temp_dir):
    """Verify Saraswati and Lakshmi suite modules in 5000_lines implementation."""
    shield = SaraswatiSuiteShield()
    test_file = temp_dir / "sample.txt"
    test_file.write_text("integrity verification test")

    sha, md5 = shield.get_file_hash(str(test_file))
    assert sha is not None and len(sha) == 64
    assert md5 is not None and len(md5) == 32

    # Check heuristic scoring
    suspicious_temp = temp_dir / "temp_bad.exe"
    suspicious_temp.write_bytes(b"MZ" + b"\x00" * 100)
    score = shield.heuristic_scan(str(suspicious_temp))
    assert score > 0

    # Check system health retrieval
    health = LakshmiSuiteGuard.get_system_health()
    assert "cpu" in health
    assert "ram" in health
    assert "disk" in health
    assert "threads" in health


def test_cli_main_run(temp_dir, caplog):
    """Verify CLI entrypoint runs without exception."""
    test_target = temp_dir / "cli_test.txt"
    test_target.write_text("clean content")

    code = cli_run([str(test_target), "--max-files", "5"])
    assert code == 0


def test_utils_is_text_file(temp_dir):
    """Verify text file detection vs binary file detection."""
    txt_file = temp_dir / "valid.txt"
    txt_file.write_text("plain utf-8 string content\nwith newlines")
    assert is_text_file(txt_file) is True

    bin_file = temp_dir / "binary.bin"
    bin_file.write_bytes(b"\x00\x01\x02\x03\xff")
    assert is_text_file(bin_file) is False

    missing_file = temp_dir / "non_existent_file.txt"
    assert is_text_file(missing_file) is False


def test_heuristics_nonexistent_file(temp_dir):
    """Verify non-existent file returns False from heuristic."""
    missing_file = temp_dir / "does_not_exist.bin"
    assert simple_heuristic(missing_file) is False


def test_signatures_nonexistent_file(temp_dir):
    """Verify non-existent file returns False from signature match."""
    missing_file = temp_dir / "does_not_exist.bin"
    assert match(missing_file) is False


def test_quarantine_error_handling(temp_dir):
    """Verify quarantine failure is logged and returns None."""
    logger = setup_logger("test_quarantine_err")
    bad_source = temp_dir / "non_existent.bin"
    res = move_to_quarantine(bad_source, logger=logger)
    assert res is None


def test_scanner_nonexistent_target(temp_dir):
    """Verify scanner handles non-existent paths gracefully."""
    logger = setup_logger("test_scanner_nonexistent")
    findings = scan_path(temp_dir / "nonexistent_dir", logger=logger)
    assert findings == []


def test_scanner_single_file_threat(temp_dir):
    """Verify scanning a single file target identified as a threat."""
    logger = setup_logger("test_single_file")
    threat = temp_dir / "virus_sample.txt"
    threat.write_text("heuristic threat")
    findings = scan_path(threat, logger=logger)
    assert len(findings) == 1
    assert findings[0]["reason"] == "heuristic"


def test_scanner_single_file_clean(temp_dir):
    """Verify scanning a single clean file target."""
    logger = setup_logger("test_single_clean")
    clean = temp_dir / "normal.txt"
    clean.write_text("clean text")
    findings = scan_path(clean, logger=logger)
    assert len(findings) == 0


def test_scanner_max_files_limit(temp_dir):
    """Verify scan honors max_files limit."""
    logger = setup_logger("test_max_files")
    for i in range(10):
        (temp_dir / f"clean_{i}.txt").write_text(f"content {i}")
    findings = scan_path(temp_dir, logger=logger, max_files=3)
    assert len(findings) == 0


def test_cli_threat_detection(temp_dir):
    """Verify CLI returns exit code 1 when threats are found."""
    threat = temp_dir / "malware_payload.bin"
    threat.write_text("malware")
    exit_code = cli_run([str(threat)])
    assert exit_code == 1


def test_scanner_permission_error(temp_dir):
    """Verify scanner handles file reading errors gracefully."""
    logger = setup_logger("test_perm_err")
    unreadable = temp_dir / "unreadable.bin"
    unreadable.write_bytes(b"some bytes")
    unreadable.chmod(0o000)
    try:
        findings = scan_path(unreadable, logger=logger)
        # Even if read fails, scanner logs error and continues safely without raising
        assert isinstance(findings, list)
    finally:
        unreadable.chmod(0o644)
