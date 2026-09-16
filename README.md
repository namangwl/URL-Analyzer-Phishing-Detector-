# URL Analyzer & Phishing Detector

![React](https://img.shields.io/badge/react-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)
![Vite](https://img.shields.io/badge/vite-%23646CFF.svg?style=for-the-badge&logo=vite&logoColor=white)

A lightweight, client-side URL scanner built with React. It analyzes links for common phishing patterns and malicious structures directly in the browser—no backend APIs required.

Live Demo: [https://url-analyzer-phishing-detector.vercel.app/](https://url-analyzer-phishing-detector.vercel.app/)

## How It Works
I wanted to build a fast validation engine that respects user privacy. Instead of sending the URL to a server, the app parses the input locally and runs it through a custom scoring logic to determine the threat level (Safe, Warning, or Critical). 

It specifically checks for:
*   **Protocol Validation:** Flags unencrypted HTTP connections.
*   **IP Masking:** Detects if a raw IP address is used instead of a proper domain (a common phishing tactic).
*   **Suspicious Keywords:** Looks for urgent or deceptive words like 'login', 'secure', 'bank', 'auth' in the URL path.
*   **URL Shorteners:** Flags hidden destinations (bit.ly, tinyurl, etc.).
*   **Domain Structure:** Catches unusually long URLs or URLs with excessive subdomains.

## Local Setup
If you want to run this locally on your machine:

1. Clone the repo:
   `git clone https://github.com/namangwl/ProStackHub_URLAnalyzer.git`
2. Install the dependencies:
   `npm install`
3. Start the dev server:
   `npm run dev`

---
