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
from vaishnavi_av.main import run as cli_run
from vaishnavi_av.quarantine import move_to_quarantine
from vaishnavi_av.scanner import scan_path
from vaishnavi_av.signatures import SAMPLE_SIGNATURES, file_hash, match


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
    # 1. Clean file
    (temp_dir / "clean.txt").write_text("All is fine.")

    # 2. EICAR signature match
    (temp_dir / "eicar.com").write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    # 3. Heuristic match
    (temp_dir / "trojan_malware.exe").write_bytes(b"binary data")

    findings = scan_path(temp_dir, max_files=50)
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

    cli_run([str(test_target), "--max-files", "5"])
