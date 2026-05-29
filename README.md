# IOC-Extractor

Ein kommandozeilenbasiertes Python-Werkzeug, das **Indicators of Compromise
(IOCs)** automatisch aus Textberichten extrahiert: IPv4-Adressen, Domains,
URLs, E-Mail-Adressen, Datei-Hashes (MD5/SHA1/SHA256) und CVE-Kennungen.

Absichtlich „entschärfte" Schreibweisen (z. B. `hxxp://`, `domain[.]com`)
werden erkannt und automatisch zurückgewandelt (Refang). Mehrfach genannte
Indikatoren werden dedupliziert; das Ergebnis erscheint gruppiert auf der
Konsole und wird zusätzlich als CSV exportiert.

## Installation

Mit conda (Python 3.12):

```bash
conda env create -f environment.yml
conda activate ioc-extractor
pip install -e .
```

## Verwendung

```bash
python -m ioc_extractor examples/threat_report_demo.txt
```

Optional ein eigenes Ziel für den CSV-Export angeben:

```bash
python -m ioc_extractor bericht.txt -o ergebnisse.csv
```

## Tests

```bash
pytest
```

## Code-Stil

Formatierung mit Black, statische Prüfung mit Ruff:

```bash
black .
ruff check .
```

## Projektstruktur

```
ioc-extractor/
├── ioc_extractor/
│   ├── models.py      # IOC-Dataclass (Datenmodell)
│   ├── patterns.py    # Regex-Muster + Refang-Normalisierung
│   ├── extractor.py   # IOCExtractor (Kernlogik)
│   └── cli.py         # Kommandozeile + Ausgabe/Export
├── tests/             # pytest-Tests
├── examples/          # Beispiel-Bericht
├── environment.yml    # conda-Umgebung (Python 3.12)
└── pyproject.toml      # Paket-, Black-, Ruff- und pytest-Konfiguration
```

## Hinweis

Alle in den Beispieldaten verwendeten IP-Adressen liegen in den laut
RFC 5737 für Dokumentation reservierten Bereichen, alle Domains enden auf
`.example`. Es werden keine realen oder erreichbaren Indikatoren verwendet.
