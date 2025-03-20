# SANO
The Swiss Army Knife For All Your OSINT Needs.  
*SANO - Swiss-Army-Knife-Needed-For-Osint*

![Preview](https://github.com/scarlmao/SANO/blob/main/image.png)

## Overview

SANO is an all-in-one OSINT tool that provides a variety of features including:
- Google Dorking
- Username Lookup
- Email Lookup
- Phone Lookup
- Court Lookup
- People Lookup
- Domain Lookup
- IP Lookup
- Discord Server Lookup
- Site Robots & Sitemap Lookup
- GitHub Lookup
- Bin Lookup
- Site Crawler
- Site Path Finder

> **Important:**  
> Before using SANO, you must update the API keys in the code.  
> If the keys are missing, the tool will prompt you to enter your Hunter and Whois API keys and store them in your local `.env` file.

## Installation

### Installing Dependencies

You can install the required dependencies using pip:

```bash
pip install pystyle requests phonenumbers bs4 python-dotenv
```

### Installing SANO via pipx
SANO is now installable as a command-line tool using pipx.

From the root directory, run:
```bash
pipx install .
```

### Usage

After installation, you can use the tool by running:
```bash
sano
```

If you have not set your API keys, you will be prompted to enter them prior to using the tool.


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=scarlmao/SANO&type=Date)](https://star-history.com/#scarlmao/SANO&Date)

This tool offers google dorking, username lookup, email lookup, phone lookup, court lookup, poeple lookup, domain lookup, ip lookup, discord server lookup, site robots and map, github lookup, bin lookup, site crawler, and site path finder