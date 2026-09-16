// Dev Note: Common keywords used in phishing/typosquatting attacks
const SUSPICIOUS_WORDS = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'auth', 'free'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd'];

export const analyzeUrl = (inputUrl) => {
    // Early bailout if empty
    if (!inputUrl.trim()) {
        return { error: "Please enter a URL to scan." };
    }

    let urlObj;
    let urlToParse = inputUrl.trim();

    // Force protocol if missing, just so the URL parser doesn't crash
    if (!urlToParse.startsWith('http://') && !urlToParse.startsWith('https://')) {
        urlToParse = 'http://' + urlToParse;
    }

    try {
        urlObj = new URL(urlToParse);
    } catch (e) {
        return { error: "Invalid URL structure. Please check for typos." };
    }

    const host = urlObj.hostname.toLowerCase();
    const fullPath = urlObj.href.toLowerCase();
    
    let riskScore = 0;
    const issuesFound = [];
    const safePoints = [];

    // 1. Protocol Check
    if (urlObj.protocol === 'https:') {
        safePoints.push("Connection is encrypted (HTTPS).");
    } else {
        riskScore += 30;
        issuesFound.push("Connection is unencrypted (HTTP). Data can be intercepted.");
    }

    // 2. IP Address in Hostname (Common phishing tactic)
    // Basic regex to catch IPv4 formats
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    if (ipRegex.test(host)) {
        riskScore += 40;
        issuesFound.push("IP Address used instead of a domain name.");
    }

    // 3. Excessive Length Check (Hiding actual domain)
    if (fullPath.length > 75) {
        riskScore += 15;
        issuesFound.push(`URL is suspiciously long (${fullPath.length} chars).`);
    }

    // 4. Multiple Subdomains Check
    const domainParts = host.split('.');
    if (domainParts.length > 3 && !host.includes('www')) {
        riskScore += 20;
        issuesFound.push("Unusually high number of subdomains detected.");
    }

    // 5. URL Shortener Check
    if (SHORTENERS.some(shortener => host.includes(shortener))) {
        riskScore += 25;
        issuesFound.push("URL Shortener used. The final destination is hidden.");
    }

    // 6. Suspicious Keywords Check
    const foundKeywords = SUSPICIOUS_WORDS.filter(word => fullPath.includes(word));
    if (foundKeywords.length > 0) {
        riskScore += 15 * foundKeywords.length;
        issuesFound.push(`Contains suspicious keywords often used in phishing: ${foundKeywords.join(', ')}`);
    }

    // Cap the max score at 100
    const finalScore = Math.min(riskScore, 100);
    
    // Determine threat level based on calculated score
    let threatLevel = 'Safe';
    if (finalScore >= 60) threatLevel = 'Critical';
    else if (finalScore >= 30) threatLevel = 'Warning';

    return {
        url: urlObj.href,
        domain: host,
        threatLevel,
        riskScore: finalScore,
        issues: issuesFound,
        positives: safePoints
    };
};