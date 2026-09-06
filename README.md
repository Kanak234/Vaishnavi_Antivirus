# Vaishnavi Antivirus

A Tkinter desktop antivirus / system-defence GUI in Python. The full project —
the main GUI, the scanner modules (`saraswati_shield.py`, `kali_defense.py`,
`lakshmi_guard.py`) and its own notes — is in
[`Vaishnavi_Antivirus_Full_GUI/`](Vaishnavi_Antivirus_Full_GUI/); see
[`Vaishnavi_Antivirus_Full_GUI/README.txt`](Vaishnavi_Antivirus_Full_GUI/README.txt).

## Run

```bash
cd Vaishnavi_Antivirus_Full_GUI
python3 vaishnavi_antivirus_5000_lines.py
```

## Requires

- Python 3 with Tkinter (hashing/file-scan uses the standard library).

## Status

A learning/security desktop project. It performs signature-style checks over
files; it is not a substitute for a production antivirus.
