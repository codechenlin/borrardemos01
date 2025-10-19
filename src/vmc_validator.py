import os, datetime, hashlib, subprocess, tempfile, requests, re, urllib.request
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509 import ocsp

# Timeouts
TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "15"))
OCSP_TIMEOUT = int(os.environ.get("OCSP_TIMEOUT", "10"))
CRL_TIMEOUT = int(os.environ.get("CRL_TIMEOUT", "10"))

# Sistema de raíces confiables
CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*"
}

def _now():
    return datetime.datetime.utcnow()

def _download(url: str, timeout: int):
    r = requests.get(url, timeout=timeout, headers=DEFAULT_HEADERS, allow_redirects=True)
    r.raise_for_status()
    return r.content

def _load_pem_cert(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes, default_backend())

def _get_aia_urls(cert: x509.Certificate):
    try:
        aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except Exception:
        return [], []
    issuers, ocsp_urls = [], []
    for access_desc in aia_ext:
        loc = getattr(access_desc.access_location, "value", "")
        if access_desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and loc.lower().startswith("http"):
            issuers.append(loc)
        if access_desc.access_method == AuthorityInformationAccessOID.OCSP and loc.lower().startswith("http"):
            ocsp_urls.append(loc)
    return issuers, ocsp_urls

def _get_crl_urls(cert: x509.Certificate):
    try:
        crldp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        urls = []
        for dp in crldp:
            for gn in dp.full_name or []:
                val = getattr(gn, "value", "")
                if val.lower().startswith("http"):
                    urls.append(val)
        return urls
    except Exception:
        return []

def _validate_times(cert: x509.Certificate) -> bool:
    # Evita deprecations usando propiedades *_utc, con fallback
    now = _now()
    try:
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_before <= now <= cert.not_valid_after

def _download_issuer_and_save(leaf_cert: x509.Certificate) -> str | None:
    issuers, _ = _get_aia_urls(leaf_cert)
    for url in issuers:
        try:
            content = _download(url, TIMEOUT)
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
            tmp.write(content)
            tmp.close()
            return tmp.name
        except Exception:
            continue
    return None

def _verify_with_openssl(vmc_bytes: bytes, issuer_path: str | None = None) -> dict:
    out = {"status": "error", "format": None, "chain_ok": None, "detail": None, "stdout": None, "stderr": None}
    # Si lo descargado es HTML (ej. 404)
    if vmc_bytes[:64].lstrip().lower().startswith(b"<html"):
        out["detail"] = "La URL devolvió HTML (404/errores), no un VMC"
        return out

    head = vmc_bytes[:128]
    is_pem_cert = b"-----BEGIN CERTIFICATE-----" in head
    looks_der = len(vmc_bytes) > 4 and vmc_bytes[0] == 0x30  # ASN.1 SEQUENCE

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(vmc_bytes)
        f.flush()
        vmc_path = f.name

    try:
        # 1) PEM X.509 directo
        if is_pem_cert:
            out["format"] = "x509_pem"
            info = subprocess.run(["openssl", "x509", "-text", "-noout", "-in", vmc_path],
                                  capture_output=True, text=True, timeout=15)
            if info.returncode == 0:
                cmd = ["openssl", "verify", "-CAfile", CA_BUNDLE]
                if issuer_path:
                    cmd.extend(["-untrusted", issuer_path])
                cmd.append(vmc_path)
                verify = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                out["stdout"] = info.stdout[:500] + "\n---\n" + verify.stdout.strip()
                out["stderr"] = verify.stderr.strip()
                out["chain_ok"] = "OK" in verify.stdout
                out["status"] = "pass" if out["chain_ok"] else "fail"

        # 2) DER X.509
        if looks_der and out["status"] == "error":
            out["format"] = "x509_der"
            info = subprocess.run(["openssl", "x509", "-text", "-noout", "-inform", "DER", "-in", vmc_path],
                                  capture_output=True, text=True, timeout=15)
            if info.returncode == 0:
                cmd = ["openssl", "verify", "-CAfile", CA_BUNDLE, "-inform", "DER"]
                if issuer_path:
                    cmd.extend(["-untrusted", issuer_path])
                cmd.append(vmc_path)
                verify = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                out["stdout"] = info.stdout[:500] + "\n---\n" + verify.stdout.strip()
                out["stderr"] = verify.stderr.strip()
                out["chain_ok"] = "OK" in verify.stdout
                out["status"] = "pass" if out["chain_ok"] else "fail"

        # 3) Si falló y NO se pasó issuer, intentar extraer AIA y reintentar
        if not out.get("chain_ok") and not issuer_path:
            try:
                proc_aia = subprocess.run(
                    ["openssl", "x509", "-in", vmc_path, "-noout", "-text"],
                    capture_output=True, text=True, timeout=15
                )
                match = re.search(r"CA Issuers - URI:(http[^\s]+)", proc_aia.stdout)
                if match:
                    aia_url = match.group(1)
                    inter_path = vmc_path + ".intermediate.pem"
                    urllib.request.urlretrieve(aia_url, inter_path)
                    proc_chain = subprocess.run(
                        ["openssl", "verify", "-CAfile", CA_BUNDLE, "-untrusted", inter_path, vmc_path],
                        capture_output=True, text=True, timeout=15
                    )
                    out["stdout"] = (out.get("stdout","") + "\n---\n" + proc_chain.stdout.strip()).strip()
                    out["stderr"] = (out.get("stderr","") + "\n---\n" + proc_chain.stderr.strip()).strip()
                    out["chain_ok"] = "OK" in proc_chain.stdout
                    out["status"] = "pass" if out["chain_ok"] else "fail"
                    out["detail"] = f"Intento con AIA desde {aia_url}"
            except Exception as e:
                out["detail"] = f"Error en validación AIA: {e}"

        if out["status"] == "error":
            out["detail"] = "Formato no reconocido o cadena no verificable con CA del sistema"
        return out
    except Exception as e:
        out["detail"] = str(e)
        return out

def check_vmc_oids(pem_bytes: bytes) -> dict:
    try:
        cert = _load_pem_cert(pem_bytes)
        # Lista de OIDs presentes en extensiones (para trazabilidad)
        oids = [ext.oid.dotted_string for ext in cert.extensions]
        return {"status": "ok", "oids": oids}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def compare_validators(py: dict, ossl: dict) -> dict:
    audit = {"match": {}, "errors": {}}
    # Comparación básica: validez temporal vs cadena de confianza
    if "valid_now" in py and "chain_ok" in ossl:
        audit["match"]["validity_vs_chain"] = (py["valid_now"] == ossl["chain_ok"])
    # Errores por validador
    if py.get("status") == "error":
        audit["errors"]["python"] = py.get("error")
    if ossl.get("status") == "error":
        audit["errors"]["openssl"] = ossl.get("error")
    return audit

def check_vmc(vmc_url: str | None, svg_url: str | None) -> dict:
    out = {
        "python": {},
        "openssl": {},
        "audit": {},
        "vmc": {},      # Bloque de compatibilidad requerido por tu contrato de API
        "message": ""
    }

    # Validaciones iniciales de URL
    if not vmc_url:
        out["message"] = "El dominio no incluye VMC (no hay campo a= en el registro BIMI)"
        out["vmc"] = {
            "exists": False,
            "authentic": False,
            "chain_ok": False,
            "valid_now": False,
            "revocation_ok": None,
            "ocsp_status": "",
            "crl_status": "",
            "vmc_logo_hash_present": False,
            "logo_hash_match": False,
            "message": out["message"],
            "retry_suggestion": None,
            "source_url": vmc_url
        }
        return out

    parsed = urlparse(vmc_url)
    if parsed.scheme != "https":
        out["message"] = "El certificado VMC debe servirse por HTTPS"
        out["vmc"] = {
            "exists": False,
            "authentic": False,
            "chain_ok": False,
            "valid_now": False,
            "revocation_ok": None,
            "ocsp_status": "",
            "crl_status": "",
            "vmc_logo_hash_present": False,
            "logo_hash_match": False,
            "message": out["message"],
            "retry_suggestion": None,
            "source_url": vmc_url
        }
        return out

    # --- BLOQUE PYTHON ---
    pem_bytes = b""
    leaf_cert = None
    try:
        pem_bytes = _download(vmc_url, TIMEOUT)
        leaf_cert = _load_pem_cert(pem_bytes)
        issuers, ocsp_urls = _get_aia_urls(leaf_cert)
        out["python"] = {
            "exists": True,
            "valid_now": _validate_times(leaf_cert),
            "subject": leaf_cert.subject.rfc4514_string(),
            "issuer": leaf_cert.issuer.rfc4514_string(),
            "oids": check_vmc_oids(pem_bytes),
            "aia_urls": issuers,
            "ocsp_urls": ocsp_urls,
            "crl_urls": _get_crl_urls(leaf_cert),
            "status": "ok"
        }
    except requests.HTTPError as e:
        out["python"] = {"status": "error", "error": f"HTTP {getattr(e.response, 'status_code', 'unknown')}"}
        out["message"] = f"No se pudo descargar el VMC (HTTP {getattr(e.response, 'status_code', 'unknown')})"
    except requests.Timeout:
        out["python"] = {"status": "error", "error": "timeout"}
        out["message"] = "No se pudo descargar el VMC (timeout)"
    except requests.RequestException as e:
        out["python"] = {"status": "error", "error": f"network_error: {e}"}
        out["message"] = "No se pudo descargar el VMC (error de red o bloqueado)"
    except Exception as e:
        out["python"] = {"status": "error", "error": str(e)}
        out["message"] = f"No se pudo procesar el VMC (error: {e})"

    # --- BLOQUE OPENSSL ---
    try:
        issuer_path = None
        if out["python"].get("status") == "ok" and leaf_cert is not None:
            issuer_path = _download_issuer_and_save(leaf_cert)
        out["openssl"] = _verify_with_openssl(pem_bytes, issuer_path)
    except Exception as e:
        out["openssl"] = {"status": "error", "error": str(e)}
        if not out["message"]:
            out["message"] = f"Error en validador OpenSSL: {e}"

    # --- COMPARADOR ---
    out["audit"] = compare_validators(out["python"], out["openssl"])

    # --- BLOQUE DE COMPATIBILIDAD VMC (siempre rellenado) ---
    vmc_exists = bool(out["python"].get("exists", False))
    vmc_valid_now = bool(out["python"].get("valid_now", False))
    vmc_chain_ok = bool(out["openssl"].get("chain_ok", False))
    vmc_authentic = bool(out["openssl"].get("status") == "pass")

    # Placeholder de revocación (mapea aquí tu lógica si la tienes en otro módulo)
    ocsp_status = ""
    crl_status = ""
    revocation_ok = None

    # Hash/logo (placeholders si aún no implementas)
    vmc_logo_hash_present = False
    logo_hash_match = False

        out["vmc"] = {
        "exists": bool(vmc_exists),
        "authentic": bool(vmc_authentic),
        "chain_ok": bool(vmc_chain_ok),
        "valid_now": bool(vmc_valid_now),
        # Forzamos a boolean en lugar de None
        "revocation_ok": bool(revocation_ok) if revocation_ok is not None else False,
        # Strings nunca deben ser None
        "ocsp_status": str(ocsp_status) if ocsp_status is not None else "",
        "crl_status": str(crl_status) if crl_status is not None else "",
        "vmc_logo_hash_present": bool(vmc_logo_hash_present),
        "logo_hash_match": bool(logo_hash_match),
        "message": out.get("message", "") or "Validación VMC completada sin errores",
        "retry_suggestion": None,
        "source_url": vmc_url or "",
        "openssl": out.get("openssl", {})
    }

    # Mensaje final coherente
    if not out["message"]:
        out["message"] = "Validación VMC completada sin errores"

    return out
