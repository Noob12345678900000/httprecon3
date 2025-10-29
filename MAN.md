# `httprecon3` – Manual Page (`man`-style)

<code>HTTPRECON3(1)               User Commands               HTTPRECON3(1)</code>

## NAME
<code>httprecon3</code> – Advanced web reconnaissance crawler with deep link extraction, API key detection, subdomain brute-forcing, screenshots, and AI reporting.

---

## SYNOPSIS
<code>python3 httprecon3.py <target> [options]</code>

---

## DESCRIPTION
<code>httprecon3</code> is a powerful, modular reconnaissance tool designed for security researchers, bug bounty hunters, and penetration testers. It crawls websites to discover hidden assets, extract sensitive data (API keys, tokens, secrets), brute-force subdomains, take full-page screenshots, and generate AI-powered summaries.

### Key Features
- 50+ link extraction methods (HTML, JS, CSS, SVG, JSON-LD, robots.txt, etc.)
- 300+ API key/secret regex patterns
- 250+ built-in subdomain wordlist
- Full-page screenshots via headless Chrome
- Stealth mode with random delays and rotating User-Agent
- AI-powered recon report (GPT-4o)
- Highly extensible

---

## OPTIONS

<code><target></code>  
&nbsp;&nbsp;&nbsp;&nbsp;Target domain or URL (e.g., <code>example.com</code> or <code>https://example.com</code>)

<code>-o, --output FILE</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Save discovered assets to file

<code>-e, --ext EXT1 EXT2 ...</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Filter assets by file extension (e.g., <code>js css json pdf</code>)

<code>-d, --depth N</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Crawl depth (default: 3)

<code>-k, --keywords KW1 KW2 ...</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Custom keywords to search (overrides default 300+)

<code>--extract-keys</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Enable detection of API keys, tokens, and secrets

<code>--screenshots DIR</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Save full-page screenshots to directory

<code>--stealth MIN MAX</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Random delay between requests in seconds (e.g., <code>1 3</code>)

<code>--subdomains</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Brute-force subdomains using built-in wordlist

<code>--wordlist FILE</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Use custom subdomain wordlist

<code>--no-ai</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Disable AI-powered report generation

<code>-h, --help</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Show help message and exit

---

## EXAMPLES

### Basic crawl
<code>python3 httprecon3.py example.com</code>

### Full recon with subdomains and screenshots
<code>python3 httprecon3.py target.com --subdomains --screenshots shots/ --extract-keys -o assets.txt</code>

### Hunt for JS files with API keys
<code>python3 httprecon3.py site.com -e js --extract-keys --stealth 2 5</code>

### Use custom wordlist and deep crawl
<code>python3 httprecon3.py app.com --subdomains --wordlist big.txt -d 5</code>

---

## OUTPUT

### Assets
All discovered URLs are printed and optionally saved via <code>-o</code>.

### Keyword Findings
Highlighted with context when <code>-k</code> or default keywords match.

### API Keys / Secrets
Detected using 300+ regex patterns when <code>--extract-keys</code> is used.

### Screenshots
Saved as PNG in the specified directory with timestamp.

### AI Report
Generated at the end unless <code>--no-ai</code> is used.

---

## FILES

<code>httprecon3.py</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Main executable script

<code>README.md</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Project documentation

<code>LICENSE</code>  
&nbsp;&nbsp;&nbsp;&nbsp;MIT License

---

## ENVIRONMENT

<code>PYTHONPATH</code>  
&nbsp;&nbsp;&nbsp;&nbsp;Ensure required packages are installed globally or in a virtual environment.

---

## DEPENDENCIES

- Python 3.8+
- requests
- beautifulsoup4
- cssutils
- selenium
- colorama
- dnspython
- (Optional) webdriver-manager

---

## SEE ALSO

<code>README.md</code>, <code>LICENSE</code>, <code>https://github.com/Noob12345678900000/httprecon3</code>

---

## AUTHOR

Written by **l0n3ly!**

- GitHub: <code>https://github.com/Noob12345678900000</code>  
- DEV.to: <code>https://dev.to/l0n3ly</code>  
- Discord: <code>l0n3ly_natasha</code>

---

## COPYRIGHT

Copyright © 2025 l0n3ly!  
This is free software; see the source for copying conditions. There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

<code>httprecon3 1.0                     October 2025                HTTPRECON3(1)</code>
