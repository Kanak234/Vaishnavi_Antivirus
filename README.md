# Vaishnavi Antivirus Suite (`vaishnavi-av`)

[![CI](https://github.com/Kanak234/Vaishnavi_Antivirus/actions/workflows/ci.yml/badge.svg)](https://github.com/Kanak234/Vaishnavi_Antivirus/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Kanak234/Vaishnavi_Antivirus/actions/workflows/codeql.yml/badge.svg)](https://github.com/Kanak234/Vaishnavi_Antivirus/actions/workflows/codeql.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Coverage: 97%](https://img.shields.io/badge/Coverage-97%25-brightgreen.svg)](#testing)

A lightweight cybersecurity and malware diagnostic suite in Python providing signature-based hash matching, heuristic file anomaly analysis, secure quarantine vault isolation, and system performance monitoring.

---

## Key Components

- **Modular Scanning Engine (`vaishnavi_av`):** High-performance CLI scanning utility with signature verification, heuristics, and automatic quarantine.
- **Quarantine Vault:** Path-isolated vault isolating detected threats from execution permissions.
- **Multi-Module Defenses:**
  - `saraswati_shield.py`: AI-inspired heuristic scoring and cryptographic hash verification.
  - `kali_defense.py`: Threat neutralization and eradication logging.
  - `lakshmi_guard.py`: Real-time system health and resource stability monitoring.
- **Desktop Studio (`Vaishnavi_Antivirus_Full_GUI`):** Tkinter graphical user interface for interactive inspection and system control.

---

## Installation

### From Source
```bash
git clone https://github.com/Kanak234/Vaishnavi_Antivirus.git
cd Vaishnavi_Antivirus
pip install .
```

### Development Mode
```bash
pip install -e .[dev]
```

---

## Usage

### Command Line Interface (CLI)

```bash
# Scan current directory
vaishnavi-av

# Scan specific target path with custom file limit
vaishnavi-av /path/to/target --max-files 500

# Display version
vaishnavi-av --version
```

### Desktop GUI Application

```bash
cd Vaishnavi_Antivirus_Full_GUI
python3 vaishnavi_antivirus_5000_lines.py
```

---

## Testing

The automated test suite exercises the modular engine, heuristics, signature matching, and CLI entry points with zero synthetic mocks:

```bash
# Run pytest with coverage
pytest -v --cov=vaishnavi_av --cov-report=term-missing

# Run linting and type-checking
ruff check .
mypy Vaishnavi_Antivirus_Full_GUI/vaishnavi_av
```

---

## Containerization

A hardened multi-stage Alpine container is provided:

```bash
# Build container image
docker build -t vaishnavi-antivirus .

# Execute scan inside container
docker run --rm -v /path/to/scan:/scan:ro vaishnavi-antivirus /scan
```

---

## Security Policy

For threat model boundaries, responsible testing guidelines, and vulnerability reporting procedures, see [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).
