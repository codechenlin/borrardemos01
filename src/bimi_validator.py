import dns.resolver
import re
from src.utils import parse_kv

def _get_txt(name: str):
    try:
        ans = dns.resolver.resolve(name, "TXT")
        return "".join([s.decode() for s in ans[0].strings])
    except Exception:
        return None

def check_bimi_record(domain: str) -> dict:
    result = {
        "exists": False,
        "syntax_ok": False,
        "raw": None,
        "parts": {},
        "message": ""   # 👈 siempre inicializado como string
    }
    name = f"default._bimi.{domain}"
    raw = _get_txt(name)
    if not raw:
        result["message"] = "No se encontró registro BIMI TXT"
        return result
    result["exists"] = True
    result["raw"] = raw
    parts = parse_kv(raw)
    result["parts"] = parts
    v_ok = parts.get("v") == "BIMI1"
    l_ok = bool(parts.get("l"))
    result["syntax_ok"] = v_ok and l_ok
    if not v_ok:
        result["message"] = "Campo v debe ser BIMI1"
    if not l_ok:
        result["message"] = "Campo l (logo) faltante o vacío"
    if not result["message"]:
        result["message"] = "Validación BIMI completada sin errores"
    return result

def check_dmarc(domain: str) -> dict:
    result = {
        "dmarc_exists": False,
        "dmarc_enforced": False,
        "dmarc_policy": None,
        "policy_ok": False,
        "policy_message": "",
        "dmarc_message": ""   # 👈 siempre string
    }
    name = f"_dmarc.{domain}"
    raw = _get_txt(name)
    if not raw:
        result["dmarc_message"] = "No se encontró registro DMARC"
        return result
    result["dmarc_exists"] = True
    result["dmarc_raw"] = raw
    policy = "none"
    for kv in raw.split(";"):
        kv = kv.strip()
        if kv.startswith("p="):
            policy = kv.split("=", 1)[1].strip().lower()
            break
    result["dmarc_policy"] = policy
    result["dmarc_enforced"] = policy in ("quarantine", "reject")

    # Validación estricta: solo p=reject es aceptado
    if policy == "reject":
        result["policy_ok"] = True
        result["policy_message"] = "Política DMARC válida: p=reject"
    else:
        result["policy_message"] = f"Política DMARC inválida para BIMI: se requiere p=reject, se encontró p={policy}"

    if not result["dmarc_enforced"]:
        result["dmarc_message"] = "DMARC debe estar en quarantine o reject para BIMI"

    if not result["dmarc_message"]:
        result["dmarc_message"] = "Validación DMARC completada sin errores"

    return result
