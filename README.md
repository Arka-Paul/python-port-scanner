# Python Port Scanner

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A fast, multithreaded Python port scanner with banner grabbing, JSON export, colorized CLI output, and optional [Shodan](https://shodan.io) intelligence lookup.


---

## Features

- Fast multithreaded port scanning
- Service banner grabbing
- Export results as `.txt` and `.json`
- Colorful CLI output (using `colorama`)
- Optional Shodan integration for enriched recon
- .env-based API key management (secure and simple)

---

## Installation

1. Clone the repo

```bash
git clone https://github.com/Arka-Paul/python-port-scanner.git
cd python-port-scanner
```

2. Install required packages

```bash
pip install -r requirements.txt
```

Make sure you are using Python 3.7 or higher.

---

## Usage

```bash
python3 Port_Scanner.py --target <ip/domain> --ports <start-end> [--json]
```

### Examples:

```bash
python3 Port_Scanner.py --target scanme.nmap.org --ports 20-80
python3 Port_Scanner.py --target scanme.nmap.org --ports 1-100 --json
```

---

## Shodan Integration

To enable Shodan lookups:

1. Create a `.env` file in the root of the project:

```env
SHODAN_API_KEY=your_actual_key_here
```

2. Run the scanner as normal. If a valid key is found, Shodan results will be printed automatically after scanning.

---

## Output

- Text results saved to: `results/scan_log_YYYYMMDD_HHMM.txt`
- JSON results saved to: `results/scan_results_YYYYMMDD_HHMM.json`

---


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Author

Made by Arka Paul

GitHub Profile: https://github.com/Arka-Paul