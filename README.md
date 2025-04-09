# Python Port Scanner

A fast, multithreaded Python-based port scanner with banner grabbing, JSON export, colorful CLI output, and optional [Shodan](https://shodan.io) intelligence lookup integration.

---

## Features

- Multithreaded TCP port scanning  
- Service banner grabbing (e.g., SSH, HTTP headers)  
- Export results as `.txt` and `.json`  
- Colorized CLI output using `colorama`  
- Shodan integration for advanced intelligence (organization, open ports, vulnerabilities)  
- Environment variable support via `.env` for secure API key storage  
- Verified compatibility with **Shodan Academic Membership API**

---

## Installation

1. **Clone the Repository**

```bash
git clone https://github.com/Arka-Paul/python-port-scanner.git
cd python-port-scanner
```

2. **Install Required Packages**

```bash
pip install -r requirements.txt
```

> ✅ Requires **Python 3.7+**

---

## Usage

```bash
python3 Port_Scanner.py --target <ip/domain> --ports <start-end> [--json]
```

### Examples

```bash
python3 Port_Scanner.py --target scanme.nmap.org --ports 20-80
python3 Port_Scanner.py --target scanme.nmap.org --ports 1-100 --json
python3 Port_Scanner.py --target scanme.nmap.org --ports 1-100 --json --shodan --output FILE_NAME_YOU_WANT_TO_SAVE_AS
```

---

## Shodan Integration

To enable Shodan lookups (optional):

1. Create a `.env` file in the project root with the following content:

```env
SHODAN_API_KEY=your_actual_key_here
```

2. If the API key is valid (especially for academic/premium users), Shodan metadata will be printed after the port scan.

---

## Output

All scan results are saved inside the `results/` folder:

- **Text Log:** `results/scan_log_YYYYMMDD_HHMM.txt`  
- **JSON Report:** `results/scan_results_YYYYMMDD_HHMM.json`

---

## Project Structure

```
python-port-scanner/
├── Port_Scanner.py
├── .env                  # API Key (not tracked by Git)
├── requirements.txt
├── results/              # Output files
├── README.md
└── LICENSE
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

## Author

**Arka Paul**  
Cybersecurity & Digital Forensics Enthusiast  
GitHub: [https://github.com/Arka-Paul](https://github.com/Arka-Paul)
