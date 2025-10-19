import requests, os, datetime, hashlib, subprocess, tempfile
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509 import ocsp

TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "15"))
OCSP_TIMEOUT = int(os.environ.get("OCSP_TIMEOUT", "10"))
CRL_TIMEOUT = int(os.environ.get("CRL_TIMEOUT", "10"))

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "*/*"
}

def _now():
    return datetime.datetime.utcnow()

def _download(url: str, timeout: int):
    r = requests.get(url, timeout=timeout, headers=DEFAULT_HEADERS, allow_redirects=True)
    r.raise_for_status()
    return r.content

def _get_aia_urls(cert: x509.Certificate):
    try:
        aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except Exception:
        aia_ext = None
    issuers, ocsp_urls = [], []
    if aia_ext:
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

def _load_pem_cert(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes, default_backend())

def _try_build_chain(leaf: x509.Certificate):
    chain = [leaf]
    issuers, ocsp_urls = _get_aia_urls(leaf)
    issuer_cert = None
    for url in issuers:
        try:
            content = _download(url, TIMEOUT)
            try:
                issuer_cert = x509.load_der_x509_certificate(content, default_backend())
            except Exception:
                issuer_cert = _load_pem_cert(content)
            chain.append(issuer_cert)
            break
        except Exception:
            continue
    return chain, ocsp_urls, issuer_cert is not None

def _validate_times(cert: x509.Certificate):
    now = _now()
    return cert.not_valid_before <= now <= cert.not_valid_after

def _ocsp_check(leaf: x509.Certificate, issuer: x509.Certificate, ocsp_url: str):
    builder = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, x509.hashes.SHA1())
    req = builder.build()
    headers = {"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"}
    try:
        resp = requests.post(ocsp_url, data=req.public_bytes(), headers=headers, timeout=OCSP_TIMEOUT)
        resp.raise_for_status()
        ocsp_resp = ocsp.load_der_ocsp_response(resp.content)
        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return None, "ocsp_unavailable"
        status = ocsp_resp.certificate_status
        if status == ocsp.OCSPCertStatus.GOOD:
            return True, "ocsp_good"
        elif status == ocsp.OCSPCertStatus.REVOKED:
            return False, "ocsp_revoked"
        else:
            return None, "ocsp_unknown"
    except requests.Timeout:
        return None, "ocsp_timeout"
    except requests.RequestException:
        return None, "ocsp_network_error"
    except Exception:
        return None, "ocsp_parse_error"

def _crl_check(leaf: x509.Certificate, issuer: x509.Certificate):
    urls = _get_crl_urls(leaf)
    if not urls:
        return None, "crl_not_present"
    for url in urls:
        try:
            content = _download(url, CRL_TIMEOUT)
            try:
                crl = x509.load_der_x509_crl(content, default_backend())
            except Exception:
                crl = x509.load_pem_x509_crl(content, default_backend())
            for revoked in crl:
                if revoked.serial_number == leaf.serial_number:
                    return False, "crl_revoked"
            return True, "crl_good"
        except requests.Timeout:
            return None, "crl_timeout"
        except requests.RequestException:
            return None, "crl_network_error"
        except Exception:
            return None, "crl_parse_error"
    return None, "crl_fetch_error"

def _extract_logo_hash(cert: x509.Certificate):
    for ext in cert.extensions:
        if ext.oid.dotted_string in ("1.3.6.1.4.1.311.2.6.1", "1.3.6.1.4.1.34380.1.1"):
            data = getattr(ext.value, "value", None)
            if isinstance(data, bytes):
                return {"oid": ext.oid.dotted_string, "raw_sha256": hashlib.sha256(data).hexdigest()}
    return None

# --- NUEVO: verificación con OpenSSL ---
import subprocess
import tempfile
import os
import re
import urllib.request

CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

def _verify_with_openssl(vmc_bytes: bytes) -> dict:
    """
    Verificación robusta con OpenSSL para VMC:
    - Detecta el formato por contenido
    - Maneja PEM/DER X.509 directo
    - Intenta PKCS7 y CMS si es necesario
    - Siempre verifica la cadena con el bundle de CAs del sistema
    - Si falla, intenta descargar el intermedio desde AIA y reintenta
    """
    out = {
        "status": "error",
        "format": None,
        "chain_ok": None,
        "detail": None,
        "stdout": None,
        "stderr": None,
    }

    # Si lo descargado es HTML (ej. error 404)
    if vmc_bytes[:64].lstrip().lower().startswith(b"<html"):
        out["detail"] = "La URL devolvió HTML (404/errores), no un VMC"
        return out

    # Heurísticas para detectar formato
    head = vmc_bytes[:128]
    is_pem_cert = b"-----BEGIN CERTIFICATE-----" in head
    is_pem_pkcs7 = b"-----BEGIN PKCS7-----" in head or b"-----BEGIN CMS-----" in head
    looks_der = len(vmc_bytes) > 4 and vmc_bytes[0] == 0x30  # ASN.1 SEQUENCE

    # Guardar en archivo temporal
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(vmc_bytes)
        f.flush()
        vmc_path = f.name

    try:
        # 1) Intentar PEM X.509 directo
        if is_pem_cert:
            out["format"] = "x509_pem"
            info = subprocess.run(
                ["openssl", "x509", "-text", "-noout", "-in", vmc_path],
                capture_output=True, text=True, timeout=15
            )
            if info.returncode == 0:
                verify = subprocess.run(
                    ["openssl", "verify", "-CAfile", CA_BUNDLE, vmc_path],
                    capture_output=True, text=True, timeout=15
                )
                out["stdout"] = (info.stdout[:500] + "\n---\n" + verify.stdout.strip())
                out["stderr"] = verify.stderr.strip()
                out["chain_ok"] = "OK" in verify.stdout
                out["status"] = "pass" if out["chain_ok"] else "fail"

        # 2) Intentar DER X.509
        if looks_der and out["status"] == "error":
            out["format"] = "x509_der"
            info = subprocess.run(
                ["openssl", "x509", "-text", "-noout", "-inform", "DER", "-in", vmc_path],
                capture_output=True, text=True, timeout=15
            )
            if info.returncode == 0:
                verify = subprocess.run(
                    ["openssl", "verify", "-CAfile", CA_BUNDLE, "-inform", "DER", vmc_path],
                    capture_output=True, text=True, timeout=15
                )
                out["stdout"] = (info.stdout[:500] + "\n---\n" + verify.stdout.strip())
                out["stderr"] = verify.stderr.strip()
                out["chain_ok"] = "OK" in verify.stdout
                out["status"] = "pass" if out["chain_ok"] else "fail"

        # 3) Intentar PKCS7 PEM
        if is_pem_pkcs7 and out["status"] == "error":
            out["format"] = "pkcs7_pem"
            extract = subprocess.run(
                ["openssl", "pkcs7", "-in", vmc_path, "-print_certs"],
                capture_output=True, text=True, timeout=15
            )
            if extract.returncode == 0 and "BEGIN CERTIFICATE" in extract.stdout:
                info = subprocess.run(
                    ["openssl", "x509", "-text", "-noout"],
                    input=extract.stdout, capture_output=True, text=True, timeout=15
                )
                verify = subprocess.run(
                    ["openssl", "verify", "-CAfile", CA_BUNDLE],
                    input=extract.stdout, capture_output=True, text=True, timeout=15
                )
                out["stdout"] = (info.stdout[:500] + "\n---\n" + verify.stdout.strip())
                out["stderr"] = verify.stderr.strip()
                out["chain_ok"] = "OK" in verify.stdout
                out["status"] = "pass" if out["chain_ok"] else "fail"

        # 4) Intentar PKCS7 DER
        if looks_der and out["status"] == "error":
            out["format"] = "pkcs7_der"
            extract = subprocess.run(
                ["openssl", "pkcs7", "-in", vmc_path, "-inform", "DER", "-print_certs"],
                capture_output=True, text=True, timeout=15
            )
            if extract.returncode == 0 and "BEGIN CERTIFICATE" in extract.stdout:
                info = subprocess.run(
                    ["openssl", "x509", "-text", "-noout"],
                    input=extract.stdout, capture_output=True, text=True, timeout=15
                )
                verify = subprocess.run(
                    ["openssl", "verify", "-CAfile", CA_BUNDLE],
                    input=extract.stdout, capture_output=True, text=True, timeout=15
                )
                out["stdout"] = (info.stdout[:500] + "\n---\n" + verify.stdout.strip())
                out["stderr"] = verify.stderr.strip()
                out["chain_ok"] = "OK" in verify.stdout
                out["status"] = "pass" if out["chain_ok"] else "fail"

        # 5) Intentar CMS DER
        if looks_der and out["status"] == "error":
            out["format"] = "cms_der"
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
                certs_out = cf.name
            cms = subprocess.run(
                ["openssl", "cms", "-verify", "-inform", "DER", "-in", vmc_path,
                 "-noverify", "-certsout", certs_out],
                capture_output=True, text=True, timeout=15
            )
            if cms.returncode == 0 and os.path.getsize(certs_out) > 0:
                info = subprocess.run(
                    ["openssl", "x509", "-text", "-noout", "-in", certs_out],
                    capture_output=True, text=True, timeout=15
                )
                verify = subprocess.run(
                    ["openssl", "verify", "-CAfile", CA_BUNDLE, certs_out],
                    capture_output=True, text=True, timeout=15
                )
                out["stdout"] = (info.stdout[:500] + "\n---\n" + verify.stdout.strip())
                out["stderr"] = (cms.stderr.strip() + "\n---\n" + verify.stderr.strip()).strip()
                out["chain_ok"] = "OK" in verify.stdout
                out["status"] = "pass" if out["chain_ok"] else "fail"

        # --- NUEVO: si falló, intentar con AIA ---
        if not out.get("chain_ok"):
            try:
                proc_aia = subprocess.run(
                    ["openssl", "x509", "-in", vmc_path, "-noout", "-text"],
                    capture_output=True, text=True, timeout=15
                )
                aia_text = proc_aia.stdout
                match = re.search(r"CA Issuers - URI:(http[^\s]+)", aia_text)
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

        # Si nada funcionó
        if out["status"] == "error":
            out["detail"] = "Formato no reconocido o cadena no verificable con CA del sistema"
        return out

    except Exception as e:
        out["detail"] = str(e)
        return out

def check_vmc_oids(pem_bytes: bytes) -> dict:
    """
    Verifica que el certificado VMC contenga los OIDs requeridos.
    Ejemplo: 1.3.6.1.4.1.53087.1.13 = Registered Mark
    """
    out = {
        "oids_present": [],
        "registered_mark_oid_ok": False,
        "message": None
    }

    try:
        cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
        subject = cert.subject

        # Recorremos todos los atributos del Subject
        for attr in subject:
            oid = attr.oid.dotted_string
            out["oids_present"].append(oid)
            if oid == "1.3.6.1.4.1.53087.1.13":
                out["registered_mark_oid_ok"] = True

        if out["registered_mark_oid_ok"]:
            out["message"] = "El certificado contiene el OID Registered Mark (1.3.6.1.4.1.53087.1.13)"
        else:
            out["message"] = "El certificado NO contiene el OID Registered Mark requerido para VMC"

    except Exception as e:
        out["message"] = f"Error al analizar OIDs: {e}"

    return out

def check_ocsp_live(cert_path: str, issuer_path: str, ocsp_url: str) -> dict:
    out = {
        "ocsp_status": None,
        "message": None
    }

    try:
        proc = subprocess.run([
            "openssl", "ocsp",
            "-issuer", issuer_path,
            "-cert", cert_path,
            "-url", ocsp_url,
            "-noverify"
        ], capture_output=True, text=True, timeout=15)

        out["ocsp_status"] = "good" if "good" in proc.stdout else "revoked" if "revoked" in proc.stdout else "unknown"
        out["message"] = proc.stdout.strip()

    except Exception as e:
        out["message"] = f"Error OCSP: {e}"

    return out

def compare_validators(python_result: dict, openssl_result: dict) -> dict:
    """
    Compara los resultados de validación de Python y OpenSSL.
    Si difieren en chain_ok, devuelve una nota de auditoría.
    """
    if python_result.get("chain_ok") != openssl_result.get("chain_ok"):
        return {
            "audit_note": "Inconsistencia detectada entre validación Python y OpenSSL"
        }
    return {}

def check_vmc(vmc_url: str | None, svg_url: str | None) -> dict:
    out = {
        "exists": False,
        "authentic": False,
        "chain_ok": False,
        "valid_now": False,
        "revocation_ok": None,
        "subject": None,
        "issuer": None,
        "valid_from": None,
        "valid_to": None,
        "ocsp_status": None,
        "ocsp_detail": None,
        "crl_status": None,
        "crl_detail": None,
        "vmc_logo_hash_present": False,
        "logo_hash_match": None,
        "message": None,
        "retry_suggestion": None,
        "source_url": vmc_url,
        "openssl": {"status": "not_run"}
    }

    # Validaciones iniciales de URL
    if not vmc_url:
        out["message"] = "El dominio no incluye VMC (no hay campo a= en el registro BIMI)"
        return out

    parsed = urlparse(vmc_url)
    if parsed.scheme != "https":
        out["message"] = "El certificado VMC debe servirse por HTTPS"
        return out

    # Descargar el VMC
    try:
        pem_bytes = _download(vmc_url, TIMEOUT)   # 👈 ahora sí definimos pem_bytes
        out["exists"] = True
    except requests.HTTPError as e:
        out["message"] = f"No se pudo descargar el VMC desde la URL indicada (HTTP {e.response.status_code})"
        return out
    except requests.Timeout:
        out["message"] = "No se pudo descargar el VMC desde la URL indicada (timeout)"
        return out
    except requests.RequestException:
        out["message"] = "No se pudo descargar el VMC desde la URL indicada (error de red o bloqueado)"
        return out
    except Exception as e:
        out["message"] = f"No se pudo descargar el VMC desde la URL indicada (error: {e})"
        return out

    # Guardar en archivo temporal para OCSP/CRL
    cert_path = "/tmp/vmc_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(pem_bytes)

    # TODO: aquí deberías obtener issuer_path y ocsp_url desde el certificado
    issuer_path = None
    ocsp_url = None

    # Validación con OpenSSL
    out["openssl"] = _verify_with_openssl(pem_bytes)

    # Verificación de OIDs
    out["oids"] = check_vmc_oids(pem_bytes)

    # Prueba de revocación activa vía OCSP
    try:
        if issuer_path and ocsp_url:
            out["ocsp_live"] = check_ocsp_live(cert_path, issuer_path, ocsp_url)
        else:
            out["ocsp_live"] = {"warning": "No se pudo determinar issuer u OCSP URL"}
    except Exception as e:
        out["ocsp_live"] = {"error": f"Error al ejecutar OCSP en vivo: {e}"}

    # Auditoría cruzada: comparar Python vs OpenSSL
    audit = compare_validators(out, out["openssl"])
    if audit:
        out.update(audit)

    return out
    
    if not vmc_url:
        out["message"] = "El dominio no incluye VMC (no hay campo a= en el registro BIMI)"
        return out

    parsed = urlparse(vmc_url)
    if parsed.scheme != "https":
        out["message"] = "El certificado VMC debe servirse por HTTPS"
        return out

    try:
        pem = _download(vmc_url, TIMEOUT)
    except requests.HTTPError as e:
        out["message"] = f"No se pudo descargar el VMC desde la URL indicada (HTTP {e.response.status_code})"
        return out
    except requests.Timeout:
        out["message"] = "No se pudo descargar el VMC desde la URL indicada (timeout)"
        return out
    except requests.RequestException:
        out["message"] = "No se pudo descargar el VMC desde la URL indicada (error de red o bloqueado)"
        return out
    except Exception as e:
        out["message"] = f"No se pudo descargar el VMC desde la URL indicada (error: {e})"
        return out

    try:
        leaf = _load_pem_cert(pem)
        out["exists"] = True
        out["subject"] = leaf.subject.rfc4514_string()
        out["issuer"] = leaf.issuer.rfc4514_string()
        out["valid_from"] = leaf.not_valid_before.isoformat()
        out["valid_to"] = leaf.not_valid_after.isoformat()
        out["valid_now"] = _validate_times(leaf)

        chain, ocsp_urls, has_issuer = _try_build_chain(leaf)
        out["chain_ok"] = has_issuer

        ocsp_ok = None
        if has_issuer and ocsp_urls:
            for url in ocsp_urls:
                ok, status = _ocsp_check(leaf, chain[1], url)
                out["ocsp_status"] = status
                if status in ("ocsp_timeout", "ocsp_network_error", "ocsp_unavailable"):
                    out["ocsp_detail"] = "Problema con el servidor OCSP de la CA (caído, lento o bloqueado)"
                    out["retry_suggestion"] = {"retry_after_seconds": 60, "max_retries": 3}
                ocsp_ok = ok
                if ok is True or ok is False:
                    break
        elif has_issuer and not ocsp_urls:
            out["ocsp_status"] = "ocsp_not_provided"

        crl_ok = None
        if has_issuer and (ocsp_ok is None or ocsp_ok is False):
            crl_ok, status = _crl_check(leaf, chain[1])
            out["crl_status"] = status
            if status in ("crl_timeout", "crl_network_error", "crl_fetch_error", "crl_not_present"):
                out["crl_detail"] = "No es posible descargar lista CRL de la CA (no presente o inaccesible)"
                if not out.get("retry_suggestion"):
                    out["retry_suggestion"] = {"retry_after_seconds": 120, "max_retries": 2}

        if ocsp_ok is True or crl_ok is True:
            out["revocation_ok"] = True
        elif ocsp_ok is False or crl_ok is False:
            out["revocation_ok"] = False
        else:
            out["revocation_ok"] = None

        logo_hash_info = _extract_logo_hash(leaf)
        out["vmc_logo_hash_present"] = bool(logo_hash_info)

        if svg_url:
            try:
                svg_bytes = _download(svg_url, TIMEOUT)
                svg_sha = hashlib.sha256(svg_bytes).hexdigest()
                if logo_hash_info and logo_hash_info.get("raw_sha256"):
                    out["logo_hash_match"] = (svg_sha == logo_hash_info["raw_sha256"])
                else:
                    out["logo_hash_match"] = None
            except Exception:
                out["logo_hash_match"] = None

        out["authentic"] = (out["valid_now"] and out["chain_ok"] and out["revocation_ok"] is True)

        if out["revocation_ok"] is None:
            out["message"] = "Revocación indeterminada por indisponibilidad OCSP/CRL de la CA"
        elif out["revocation_ok"] is False:
            out["message"] = "Certificado VMC marcado como revocado por OCSP/CRL"
        elif not out["valid_now"]:
            out["message"] = "Certificado VMC fuera de vigencia"
        elif not out["chain_ok"]:
            out["message"] = "No se pudo construir la cadena hasta el emisor"
        elif out["authentic"]:
            out["message"] = "VMC autenticado con cadena y verificación de revocación"
        else:
            out["message"] = "VMC no autenticado por condiciones no cumplidas"

    except Exception as e:
        out["message"] = f"Error al parsear el VMC: {e}"

    # --- Añadir bloque de verificación con OpenSSL (siempre se ejecuta) ---
    try:
        out["openssl"] = _verify_with_openssl(pem)
    except Exception as e:
        out["openssl"] = {"status": "error", "detail": str(e)}

    return out
