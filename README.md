# httprecon3.py – Advanced Web Reconnaissance Tool

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Features](https://img.shields.io/badge/features-crawl%20%7C%20api%20keys%20%7C%20subdomains%20%7C%20screenshots%20%7C%20stealth-orange)

**httprecon3.py** is a powerful, modular, and stealthy reconnaissance crawler designed for security researchers, bug bounty hunters, and penetration testers. It discovers hidden assets, extracts sensitive data (API keys, tokens, secrets), brute-forces subdomains, takes screenshots, and generates AI-powered reports — all in one script.

---

## Features

| Feature | Description |
|-------|-----------|
| **Deep Crawling** | Recursively crawls HTML, CSS, JS, JSON, and more up to configurable depth |
| **50+ Link Types** | Extracts URLs from `<script>`, `<img>`, `srcset`, `data-src`, CSS `url()`, JS strings, SVG, Web App Manifest, `robots.txt`, and more |
| **300+ API Key Patterns** | Detects AWS, Firebase, Stripe, Slack, Google, Twilio, GitHub, and 100+ other secrets |
| **Subdomain Brute-Force** | 250+ built-in wordlist + custom wordlists with multithreaded DNS resolution |
| **Stealth Mode** | Random delays, rotating User-Agents, and headless Chrome for evasion |
| **Screenshots** | Full-page screenshots using Selenium (headless) |
| **Keyword Hunting** | 300+ regex patterns for `.env`, `/admin`, backups, debug, config files, etc. |
| **JavaScript Parsing** | Extracts URLs from `fetch()`, `axios`, `import()`, template literals, WebSocket, etc. |
| **AI-Powered Report** | Summarizes findings with GPT-4o via Pollinations API |
| **Extensible** | Easy to add new patterns, wordlists, or modules |

---

## Installation

<code>git clone https://github.com/yourusername/httprecon3.py.git</code>  
<code>cd httprecon3.py</code>

### Requirements

<code>pip install requests beautifulsoup4 cssutils selenium colorama dnspython</code>

> **ChromeDriver**: Required for screenshots.  
> Download from: https://chromedriver.chromium.org/downloads  
> Or use `webdriver-manager`:

<code>pip install webdriver-manager</code>

Then modify the script to auto-manage ChromeDriver:

<code>from webdriver_manager.chrome import ChromeDriverManager  
service = Service(ChromeDriverManager().install())  
driver = webdriver.Chrome(service=service, options=options)</code>

---

## Usage

<code>python3 httprecon3.py [URL] [OPTIONS]</code>

### Examples

<code># Basic crawl  
python3 httprecon3.py example.com</code>

<code># Crawl with custom depth, extensions, and output  
python3 httprecon3.py example.com -d 2 -e js css json -o assets.txt</code>

<code># Hunt for secrets + API keys  
python3 httprecon3.py example.com --extract-keys -k password token api_key</code>

<code># Brute-force subdomains + screenshots  
python3 httprecon3.py example.com --subdomains --screenshots</code>

<code># Full recon with stealth and AI report  
python3 httprecon3.py example.com \  
  --subdomains \  
  --extract-keys \  
  --screenshots shots/ \  
  --stealth 2 5 \  
  --wordlist big-wordlist.txt</code>

---

## Command Line Options

| Option | Description |
|------|-----------|
| `url` | Target URL or domain |
| `-o, --output` | Save discovered assets to file |
| `-e, --ext` | Filter assets by extension (`js css png pdf`) |
| `-d, --depth` | Crawl depth (default: 3) |
| `-k, --keywords` | Custom keywords to hunt |
| `--extract-keys` | Enable API key extraction |
| `--screenshots` | Directory to save full-page screenshots |
| `--stealth MIN MAX` | Random delay between requests (seconds) |
| `--subdomains` | Brute-force subdomains |
| `--wordlist FILE` | Custom subdomain wordlist |
| `--no-ai` | Disable AI report |

---

## Sample Output

<code>[+] Starting recon on: https://example.com  
[+] Domain: example.com | Depth: 3 | Stealth: 1.0-3.0s  
[+] Brute-forcing subdomains for example.com...  
[+] Found 12 valid subdomains  
[+] Subdomain: https://api.example.com  
[+] Subdomain: https://admin.example.com  

[+] Found 842 unique assets:  

https://example.com/assets/app.js  
https://cdn.example.com/style.css  
https://api.example.com/v1/users  
...  

============================================================  
 KEYWORD FINDINGS (7)  
============================================================  
URL: https://example.com/config.js  
Keyword: .env | Line 42 | Match: .env.production  
Context:  
const ENV = '.env.production';  
...  

============================================================  
 POTENTIAL API KEYS (3)  
============================================================  
URL: https://example.com/main.js  
Type: AWS Access Key | Line 128 | Key: AKIAxxxxxxxxxxxxxxxx  
Context:  
const AWS_KEY = "AKIAxxxxxxxxxxxxxxxx";  
...  

============================================================  
AI RECON REPORT  
============================================================  
High-value assets discovered: admin panel, API endpoints, S3 bucket.  
Critical: AWS keys exposed in JS. Immediate rotation required.  
Next steps: Test admin login, enumerate API, check bucket permissions.</code>

---

## Wordlists & Patterns

- `SUBDOMAIN_WORDLIST`: 250+ common subdomains (api, admin, dev, staging, etc.)
- `DEFAULT_KEYWORDS`: 300+ sensitive file/path patterns
- `API_KEY_PATTERNS`: 300+ regexes for secrets, tokens, keys

> Easily extend by editing the lists in the script.

---

## Screenshots

Screenshots are saved in the specified directory:

<code>screenshots/  
├── example.com_1700000000.png  
├── admin.example.com_1700000001.png  
└── api.example.com_1700000002.png</code>

---

## Disclaimer

This tool is for **authorized security testing only**.  
Do **not** use on systems you do not own or have permission to test.

---

## Contributing

1. Fork it
2. Create your feature branch (<code>git checkout -b feature/new-patterns</code>)
3. Commit (<code>git commit -m 'Add new API key patterns'</code>)
4. Push (<code>git push origin feature/new-patterns</code>)
5. Open a Pull Request

---

## License

<code>MIT License</code>

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/httprecon3.py&type=Date)](https://star-history.com/#yourusername/httprecon3.py&Date)

---

**Made for hunters. Built to find what others miss.**

---
