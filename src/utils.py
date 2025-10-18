import re

def safe_domain(domain: str) -> bool:
    if len(domain) > 253 or ".." in domain:
        return False
    pattern = r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
    return re.match(pattern, domain) is not None

def parse_kv(record: str):
    parts = {}
    for frag in record.split(";"):
        frag = frag.strip()
        if "=" in frag:
            k, v = frag.split("=", 1)
            parts[k.strip()] = v.strip()
    return parts

def overall_status(report: dict) -> str:
    bimi_ok = report["bimi"].get("exists") and report["bimi"].get("syntax_ok") and report["bimi"].get("dmarc_enforced")
    svg_ok = report["svg"].get("exists") and report["svg"].get("compliant")
    vmc = report["vmc"]
    vmc_exists = vmc.get("exists")
    vmc_auth = vmc.get("authentic")
    vmc_rev = vmc.get("revocation_ok")
    vmc_chain = vmc.get("chain_ok")
    vmc_valid = vmc.get("valid_now")

    if bimi_ok and svg_ok and vmc_exists and vmc_auth and vmc_rev is True and vmc_chain and vmc_valid:
        return "pass"
    if bimi_ok and svg_ok and not vmc_exists:
        return "pass_without_vmc"
    if bimi_ok and svg_ok and vmc_exists and vmc_rev is None:
        return "indeterminate_revocation"
    return "fail"

def make_recommendations(report: dict) -> dict:
    rec = {}
    vmc = report.get("vmc", {})
    retry = vmc.get("retry_suggestion")
    if retry:
        rec["retry"] = retry
    if report["bimi"].get("dmarc_enforced") is False:
        rec["dmarc"] = "Configura DMARC en quarantine o reject para habilitar BIMI."
    if report["svg"].get("compliant") is False:
        rec["svg"] = "Ajusta el SVG a BIMI-safe: sin script/foreignObject/image, sin url() en estilos, con viewBox."
    if vmc.get("exists") and (vmc.get("chain_ok") is False):
        rec["chain"] = "Incluye el certificado del emisor (AIA CA Issuers) y asegúrate de que la raíz sea confiable."
    if vmc.get("revocation_ok") is None:
        rec["revocation"] = "OCSP/CRL indisponible; reintenta según 'retry_suggestion' o valida manualmente."
    return rec
