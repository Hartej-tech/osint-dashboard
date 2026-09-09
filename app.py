from flask import Flask, render_template, request, jsonify
import whois, socket, requests, re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["30 per hour"])


def normalize_domain(raw):
    d = raw.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0]
    d = re.sub(r'^www\.', '', d)
    return d


def format_date(date_val):
    if isinstance(date_val, list):
        date_val = date_val[0] if date_val else None
    if date_val is None:
        return "Not available"
    try:
        return date_val.strftime("%d %b %Y")
    except AttributeError:
        return str(date_val)


def format_nameservers(ns_val):
    if not ns_val:
        return "Not available"
    if isinstance(ns_val, list):
        cleaned = sorted(set(ns.lower() for ns in ns_val))
        return ", ".join(cleaned)
    return str(ns_val)


def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar or "Not available",
            "creation_date": format_date(w.creation_date),
            "expiration_date": format_date(w.expiration_date),
            "name_servers": format_nameservers(w.name_servers)
        }
    except Exception as e:
        return {"error": str(e)}


def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
        return {
            "ip": ip,
            "country": res.get("country"),
            "region": res.get("regionName"),
            "city": res.get("city"),
            "isp": res.get("isp"),
            "org": res.get("org")
        }
    except Exception as e:
        return {"error": str(e)}


def get_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=10).json()
        subs = set()
        for entry in res:
            for name in entry.get("name_value", "").split("\n"):
                subs.add(name.strip())
        return sorted(subs)
    except Exception as e:
        return {"error": str(e)}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/lookup', methods=['POST'])
@limiter.limit("10 per minute")
def lookup():
    domain = normalize_domain(request.json['domain'])
    return jsonify({
        "whois": get_whois(domain),
        "ip_info": get_ip_info(domain),
        "subdomains": get_subdomains(domain)
    })


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
