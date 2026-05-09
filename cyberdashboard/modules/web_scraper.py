import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin


def scrape_website(url):

    result = {
        "url": url,
        "links": [],
        "images": [],
        "forms": [],
        "ips": [],
        "threats": []
    }

    try:
        # ✅ Fix URL
        if not url.startswith("http"):
            url = "http://" + url

        response = requests.get(url, timeout=5)
        html = response.text

        soup = BeautifulSoup(html, "html.parser")

        # 🔗 Extract links (unique)
        links = set()
        for a in soup.find_all("a", href=True):
            full_link = urljoin(url, a["href"])
            links.add(full_link)

        result["links"] = list(links)[:10]

        # 🖼 Extract images (unique)
        images = set()
        for img in soup.find_all("img", src=True):
            full_img = urljoin(url, img["src"])
            images.add(full_img)

        result["images"] = list(images)[:10]

        # 📄 Extract meaningful forms only
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method")

            if action or method:
                forms.append({
                    "action": action if action else "N/A",
                    "method": method if method else "GET"
                })

        result["forms"] = forms[:5]

        # 🌐 Extract IPs
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", html)
        result["ips"] = list(set(ips))[:5]

        # 🚨 Threat detection (keywords)
        suspicious_keywords = [
            "login", "admin", "password",
            "token", "csrf", "auth",
            "session", "redirect"
        ]

        for word in suspicious_keywords:
            if word in html.lower():
                result["threats"].append(f"⚠️ Suspicious keyword: {word}")

        # 🚨 Suspicious links detection
        for link in result["links"]:
            if "login" in link or "verify" in link or "secure" in link:
                result["threats"].append(f"⚠️ Suspicious link: {link}")

        # ✅ No threats case
        if not result["threats"]:
            result["threats"].append("✅ No major threats detected")

    except Exception as e:
        result["error"] = str(e)

    return result