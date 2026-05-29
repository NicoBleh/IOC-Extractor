# IOC-Extractor

A command-line Python tool that automatically extracts **Indicators of Compromise
(IOCs)** from text reports: IPv4 addresses, domains, URLs, email addresses,
file hashes (MD5/SHA1/SHA256), and CVE identifiers.

Intentionally "defanged" representations (e.g. `hxxp://`, `domain[.]com`)
are detected and automatically restored (refanged). Duplicate indicators
are deduplicated; the results are printed grouped to the console and also
exported as CSV.

## Installation

With conda (Python 3.12):

```bash
conda env create -f environment.yml
conda activate ioc-extractor
pip install -e .
```

## Usage

```bash
python -m ioc_extractor examples/threat_report_demo.txt
```

Optionally specify a custom path for the CSV export:

```bash
python -m ioc_extractor report.txt -o results.csv
```

## Tests

```bash
pytest
```

## Code Style

Formatting with Black, static analysis with Ruff:

```bash
black .
ruff check .
```

## Project Structure

```
ioc-extractor/
├── ioc_extractor/
│   ├── models.py      # IOC dataclass (data model)
│   ├── patterns.py    # Regex patterns + refang normalization
│   ├── extractor.py   # IOCExtractor (core logic)
│   └── cli.py         # Command-line interface + output/export
├── tests/             # pytest tests
├── examples/          # Sample reports
├── environment.yml    # conda environment (Python 3.12)
└── pyproject.toml     # Package, Black, Ruff, and pytest configuration
```

## Note

All IP addresses used in the example data fall within the ranges reserved for
documentation purposes per RFC 5737, and all domains end in `.example`.
No real or reachable indicators are used.
