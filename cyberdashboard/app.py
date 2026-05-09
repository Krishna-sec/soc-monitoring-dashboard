from flask import Flask, render_template, request, send_file, redirect, url_for, jsonify, session
import os
import json
import csv

from modules.log_analyzer import analyze_logs
from modules.network_scanner import scan_ports
from modules.packet_analyzer import analyze_packets, live_capture
from modules.web_scraper import scrape_website

app = Flask(__name__)

# 🔐 SECRET KEY (required for sessions)
app.secret_key = "super_secret_key_change_this"

# 📂 Folder setup
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# 🧠 Store state
state = {
    "logs": None,
    "packets": None,
    "live_packets": None,
    "scan": None,
    "target": None,
    "scrape": None
}

# -------------------------------
# 🔹 LOGIN
# -------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        session["logged_in"] = True   # store login session
        return redirect(url_for("dashboard"))
    return render_template("login.html")


# -------------------------------
# 🔹 SIGNUP
# -------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        return redirect(url_for("login"))
    return render_template("signup.html")


# -------------------------------
# 🔹 FORGOT PASSWORD
# -------------------------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        return redirect(url_for("login"))
    return render_template("forgot.html")


# -------------------------------
# 🔹 LOGOUT
# -------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -------------------------------
# 🔹 DASHBOARD (PROTECTED)
# -------------------------------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    # 🔐 Protect route
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("logfile")

        if file and file.filename:
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(filepath)
            state["logs"] = analyze_logs(filepath)

    return render_template(
        "index.html",
        results=state["logs"],
        packet_results=state["packets"],
        live_packets=state["live_packets"],
        scan_results=state["scan"],
        target=state["target"],
        scrape=state["scrape"]
    )


# -------------------------------
# 🔹 NETWORK SCAN
# -------------------------------
@app.route("/scan", methods=["POST"])
def scan():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    target = request.form.get("target")

    if not target:
        return "⚠️ No target provided!"

    state["target"] = target
    state["scan"] = scan_ports(target)

    return redirect(url_for("dashboard"))


# -------------------------------
# 🔹 OFFLINE PACKET ANALYSIS
# -------------------------------
@app.route("/packet", methods=["POST"])
def packet():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    file = request.files.get("packetfile")

    if file and file.filename.endswith(".pcap"):
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)
        state["packets"] = analyze_packets(filepath)
    else:
        state["packets"] = [{
            "attacks": ["Invalid File"],
            "payload": "Upload .pcap file only"
        }]

    return redirect(url_for("dashboard"))


# -------------------------------
# 🔹 LIVE PACKET SNIFFING
# -------------------------------
@app.route("/live", methods=["POST"])
def live():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    target_ip = request.form.get("target_ip")

    if not target_ip:
        return "⚠️ No target IP provided!"

    try:
        result = live_capture(target_ip, count=20, timeout=30)

        if result.get("error"):
            state["live_packets"] = {
                "error": result["error"],
                "packets": []
            }
        else:
            state["live_packets"] = result["packets"]

    except Exception as e:
        state["live_packets"] = {
            "error": str(e),
            "packets": []
        }

    return redirect(url_for("dashboard"))


# -------------------------------
# 🔹 WEB SCRAPING
# -------------------------------
@app.route("/web-scrape", methods=["POST"])
def web_scrape():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    url = request.form.get("url")

    if not url:
        return "⚠️ No URL provided!"

    if not url.startswith("http"):
        url = "http://" + url

    state["scrape"] = scrape_website(url)

    return redirect(url_for("dashboard"))


# -------------------------------
# 🔹 DOWNLOAD JSON REPORT
# -------------------------------
@app.route("/download")
def download_report():
    if not any(state.values()):
        return "⚠️ No data available!"

    filename = os.path.join(REPORT_FOLDER, "report.json")

    with open(filename, "w") as f:
        json.dump(state, f, indent=4, default=str)

    return send_file(filename, as_attachment=True)


# -------------------------------
# 🔹 DOWNLOAD CSV REPORT
# -------------------------------
@app.route("/download-csv")
def download_csv():
    filename = os.path.join(REPORT_FOLDER, "report.csv")

    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Type", "Details"])

        if state["scan"]:
            for port in state["scan"]:
                writer.writerow(["Open Port", port])

        if state["logs"] and state["logs"].get("brute_force"):
            for item in state["logs"]["brute_force"]:
                writer.writerow(["Brute Force", f"{item['ip']} - {item['attempts']} attempts"])

    return send_file(filename, as_attachment=True)


# -------------------------------
# 🔹 API STATUS (BONUS)
# -------------------------------
@app.route("/api/status")
def api_status():
    return jsonify({
        "status": "running",
        "threats": len(state["logs"]["brute_force"]) if state["logs"] else 0,
        "packets": len(state["live_packets"]) if isinstance(state["live_packets"], list) else 0
    })


# -------------------------------
# 🔹 RESET DASHBOARD (BONUS)
# -------------------------------
@app.route("/reset")
def reset():
    global state
    state = {
        "logs": None,
        "packets": None,
        "live_packets": None,
        "scan": None,
        "target": None,
        "scrape": None
    }
    return redirect(url_for("dashboard"))


# -------------------------------
# 🔹 RUN APP
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)