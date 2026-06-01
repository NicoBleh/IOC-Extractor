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
ioc-extractor examples/threat_report_demo.txt
```

Or via the module:

```bash
python -m ioc_extractor examples/threat_report_demo.txt
```

Optionally specify a custom path for the CSV export:

```bash
ioc-extractor report.txt -o results.csv
```

### Supported input formats

| Extension | Handling |
|-----------|----------|
| `.txt`, `.log`, and others | Read as plain text |
| `.eml` | RFC 2822 email parsed via stdlib `email`; MIME parts are decoded (including base64/quoted-printable), headers are included |

```bash
ioc-extractor examples/phishing_email_demo.eml
```

### Reputation enrichment (optional)

Enrich extracted IPv4 IOCs with live AbuseIPDB reputation data using the
`--enrich` flag. Requires `ABUSEIPDB_API_KEY` to be set (via `.env` or
environment variable — see `.env.example`).

```bash
ioc-extractor report.txt --enrich
```

When enrichment is active, each IPv4 address is annotated inline in the console
output (`[AbuseIPDB: MALICIOUS 95%]`) and two extra columns
(`abuseipdb_verdict`, `abuseipdb_score`) are added to the CSV export.

## Tests

```bash
pytest
```

The test suite covers regex detection, refanging, deduplication, MIME parsing,
and enrichment logic (API calls are mocked — no real keys required).

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
│   ├── models.py      # IOC dataclass
│   ├── patterns.py    # Regex patterns + refang normalization
│   ├── extractor.py   # IOCExtractor (core logic)
│   ├── reader.py      # Format-aware file reader (.txt, .eml, …)
│   ├── enricher.py    # Reputation enrichment (AbuseIPDB)
│   └── cli.py         # Command-line interface + output/export
├── test_extractor.py  # pytest test suite
├── examples/          # Sample reports and expected CSV outputs
├── .env.example       # API key template
├── environment.yml    # conda environment (Python 3.12)
└── pyproject.toml     # Package, Black, Ruff, and pytest configuration
```

## Note

All IP addresses used in the example data fall within the ranges reserved for
documentation purposes per RFC 5737, and all domains end in `.example`.
No real or reachable indicators are used.
