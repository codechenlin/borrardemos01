from flask import Flask, request, jsonify
from src.security import require_api_key, cors_headers
from src.bimi_validator import check_bimi_record, check_dmarc
from src.svg_rules import check_svg
from src.vmc_validator import check_vmc
from src.utils import safe_domain, overall_status, make_recommendations
from src.storage import init_db, save_report, cleanup_old, get_logs
from src.dns_inspector import inspect_dns

import os

app = Flask(__name__)

# Inicializar base de datos al arranque (Flask 3 ya no soporta before_first_request)
init_db()

@app.after_request
def add_cors(response):
    cors_headers(response)
    return response

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.get("/validate")
@require_api_key
def validate():
    domain = request.args.get("domain", "").strip()
    if not domain or not safe_domain(domain):
        return jsonify({"error": "Parámetro 'domain' inválido"}), 400

    report = {"domain": domain, "dns": {}, "bimi": {}, "svg": {}, "vmc": {}}

    # DNS extraction: BIMI/DMARC/MX + vmc_url_from_bimi
    dns_info = inspect_dns(domain)
    report["dns"] = dns_info

    bimi = check_bimi_record(domain)
    report["bimi"].update(bimi)

    dmarc = check_dmarc(domain)
    report["bimi"].update(dmarc)

    svg_url = bimi.get("parts", {}).get("l")
    if svg_url:
        svg = check_svg(svg_url)
        report["svg"].update(svg)
    else:
        report["svg"].update({
            "exists": False,
            "compliant": False,
            "message": "No se encontró URL de logo (l) en el registro BIMI"
        })

    vmc_url = bimi.get("parts", {}).get("a") or dns_info.get("vmc_url_from_bimi")
    vmc = check_vmc(vmc_url, svg_url)
    report["vmc"].update(vmc)

    report["status"] = overall_status(report)
    report["recommendations"] = make_recommendations(report)

    save_report(domain, report)
    retention_days = int(os.environ.get("RETENTION_DAYS", "2"))
    cleanup_old(retention_days)

    return jsonify(report), 200

@app.get("/logs")
@require_api_key
def logs():
    domain = request.args.get("domain")
    days = int(request.args.get("days", os.environ.get("RETENTION_DAYS", "2")))
    results = get_logs(domain, days)
    return jsonify({
        "count": len(results),
        "logs": results
    }), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
