# phishing_email_detector
This Python script asks the user to enter an email sender’s address and message, then checks them for common phishing warning signs. It looks for urgent language, requests for sensitive information, and suspicious links, such as shortened URLs or links that don’t use HTTPS. The script runs locally: it doesn’t send the email anywhere or open any links. Its results are a screening aid, not proof that an email is safe or malicious.



import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

URGENT_PHRASES = [
    "act now", "urgent", "immediately", "account suspended",
    "verify your account", "password expires", "payment overdue",
    "within 24 hours",
]

SENSITIVE_REQUESTS = [
    "enter your password", "send your password", "share your password",
    "confirm your login", "verify your identity", "provide your credentials",
    "send your social security", "enter your credit card",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly",
    "buff.ly", "cutt.ly", "rebrand.ly",
}


def extract_urls(text):
    return URL_RE.findall(text)


def inspect_url(url):
    """Return warning messages for a URL without visiting it."""
    warnings = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if not host:
        return ["Link has no recognizable hostname"]

    if parsed.scheme.lower() != "https":
        warnings.append("Link does not use HTTPS")

    if host in SHORTENERS:
        warnings.append("Link uses a URL-shortening service")

    if host.startswith("xn--") or ".xn--" in host:
        warnings.append("Hostname contains an internationalized (punycode) label")

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        warnings.append("Link uses a numeric IP address instead of a domain")

    if "@" in parsed.netloc:
        warnings.append("Link contains an @ sign in its network location")

    return warnings


def check_email(sender, message):
    findings = []
    text = message.lower()

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender.strip()):
        findings.append("Sender address does not look like a valid email address")

    for phrase in URGENT_PHRASES:
        if phrase in text:
            findings.append(f"Urgency language: “{phrase}”")

    for phrase in SENSITIVE_REQUESTS:
        if phrase in text:
            findings.append(f"Request for sensitive information: “{phrase}”")

    urls = extract_urls(message)
    for url in urls:
        for warning in inspect_url(url):
            findings.append(f"{warning}: {url}")

    if not findings:
        findings.append("No listed warning signs found")

    return findings, urls


def main():
    sender = input("Sender email address: ").strip()
    print("Paste the email message, then press Enter on a blank line to finish:")

    lines = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)

    findings, urls = check_email(sender, "\n".join(lines))

    print("\nScreening results:")
    for finding in findings:
        print(f"- {finding}")

    if urls:
        print("\nLinks found (not opened):")
        for url in urls:
            print(f"- {url}")

    print("\nNever enter passwords or payment details through a link in an unexpected email.")


if __name__ == "__main__":
    main()




