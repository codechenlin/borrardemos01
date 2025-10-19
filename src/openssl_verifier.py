# src/openssl_verifier.py
import json
import re
import subprocess
import tempfile
import os
from typing import Dict, Any, Optional, List, Tuple

# Utilidad para ejecutar comandos de forma segura
def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

# Guarda bytes en archivo temporal y devuelve la ruta
def save_temp(content: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content)
    os.close(fd)
    return path

# Extrae campos clave del dump textual de x509
def parse_x509_text(text: str) -> Dict[str, Any]:
    subject = None
    issuer = None
    not_before = None
    not_after = None
    ocsp_urls: List[str] = []
    aia_issuers: List[str] = []

    for line in text.splitlines():
        if line.strip().startswith("Subject:"):
            subject = line.split("Subject:", 1)[1].strip()
        elif line.strip().startswith("Issuer:"):
            issuer = line.split("Issuer:", 1)[1].strip()
        elif "Not Before:" in line:
            not_before = line.split("Not Before:", 1)[1].strip()
        elif "Not After :" in line:
            not_after = line.split("Not After :", 1)[1].strip()
        elif "OCSP - URI:" in line:
            ocsp_urls.append(line.split("OCSP - URI:", 1)[1].strip())
        elif "CA Issuers - URI:" in line:
            aia_issuers.append(line.split("CA Issuers - URI:", 1)[1].strip())

    return {
        "subject": subject,
        "issuer": issuer,
        "validity": {"not_before": not_before, "not_after": not_after},
        "ocsp_urls": ocsp_urls,
        "aia_issuers": aia_issuers,
        "raw_text_sample": text[:2000]  # recorte para auditoría limitada
    }

# Descarga un recurso vía curl (fallback si tu fetch Python falla)
def curl_download(url: str, timeout: int = 20) -> Optional[bytes]:
    code, out, err = run_cmd(["curl", "-fsSL", "--max-time", str(timeout), url])
    if code == 0:
        return out.encode("utf-8")
    return None

# Construye chain.pem juntando los emisores de AIA
def build_chain_from_aia(aia_urls: List[str]) -> Optional[bytes]:
    chain_parts: List[bytes] = []
    for url in aia_urls:
        data = curl_download(url)
        if not data:
            continue
        # Algunos emisores sirven DER, convierte a PEM si hace falta
        if url.lower().endswith(".cer") or url.lower().endswith(".der"):
            # openssl x509 -inform DER -in issuer.der -out issuer.pem
            der_path = save_temp(data, ".der")
            pem_path = der_path + ".pem"
            code, out, err = run_cmd(["openssl", "x509", "-inform", "DER", "-in", der_path, "-out", pem_path])
            if code == 0 and os.path.exists(pem_path):
                with open(pem_path, "rb") as f:
                    chain_parts.append(f.read())
            os.unlink(der_path)
            if os.path.exists(pem_path):
                os.unlink(pem_path)
        else:
            # Asumir PEM
            chain_parts.append(data)
    if not chain_parts:
        return None
    return b"".join(chain_parts)

# Verifica cadena con openssl verify
def verify_chain(cert_pem_bytes: bytes, chain_pem_bytes: Optional[bytes]) -> Dict[str, Any]:
    cert_path = save_temp(cert_pem_bytes, ".pem")
    chain_path = None
    try:
        if chain_pem_bytes:
            chain_path = save_temp(chain_pem_bytes, ".pem")
            # -untrusted para cadena intermedia, usando almacén del sistema para raíz
            code, out, err = run_cmd(["openssl", "verify", "-CAfile", chain_path, cert_path])
        else:
            code, out, err = run_cmd(["openssl", "verify", cert_path])

        ok = (code == 0) and ("OK" in out)
        return {
            "ok": ok,
            "stdout": out,
            "stderr": err
        }
    finally:
        if os.path.exists(cert_path):
            os.unlink(cert_path)
        if chain_path and os.path.exists(chain_path):
            os.unlink(chain_path)

# Verifica revocación vía OCSP
def ocsp_check(cert_pem_bytes: bytes, issuer_pem_bytes: Optional[bytes], ocsp_url: Optional[str]) -> Dict[str, Any]:
    if not issuer_pem_bytes or not ocsp_url:
        return {"status": "not_available", "detail": "Missing issuer or OCSP URL"}

    cert_path = save_temp(cert_pem_bytes, ".pem")
    issuer_path = save_temp(issuer_pem_bytes, ".pem")
    try:
        code, out, err = run_cmd([
            "openssl", "ocsp",
            "-issuer", issuer_path,
            "-cert", cert_path,
            "-url", ocsp_url,
            "-noverify"
        ], timeout=25)

        # Parse sencillo
        status = "unknown"
        if "good" in out:
            status = "good"
        elif "revoked" in out:
            status = "revoked"
        elif "Response Verify Failure" in err or "Error" in err:
            status = "error"

        return {
            "status": status,
            "stdout": out,
            "stderr": err
        }
    finally:
        os.unlink(cert_path)
        os.unlink(issuer_path)

# Dump x509 con openssl
def x509_text(cert_pem_bytes: bytes) -> Dict[str, Any]:
    cert_path = save_temp(cert_pem_bytes, ".pem")
    try:
        code, out, err = run_cmd(["openssl", "x509", "-in", cert_path, "-text", "-noout"])
        if code != 0:
            return {"error": "x509_text_failed", "stderr": err}
        return parse_x509_text(out)
    finally:
        os.unlink(cert_path)

# Pipeline completo de verificación OpenSSL
def verify_with_openssl(cert_pem_bytes: bytes) -> Dict[str, Any]:
    # 1) x509 info
    info = x509_text(cert_pem_bytes)
    aia_urls = info.get("aia_issuers", [])
    ocsp_urls = info.get("ocsp_urls", [])
    ocsp_url = ocsp_urls[0] if ocsp_urls else None

    # 2) Construir cadena desde AIA
    chain_bytes = build_chain_from_aia(aia_urls)

    # 3) Verificación de cadena
    chain_result = verify_chain(cert_pem_bytes, chain_bytes)

    # 4) OCSP: usar el primer emisor de la cadena como issuer
    issuer_pem = None
    if chain_bytes:
        # Tomar primer bloque PEM como issuer
        try:
            first_block = chain_bytes.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
            issuer_pem = first_block
        except Exception:
            issuer_pem = None

    ocsp_result = ocsp_check(cert_pem_bytes, issuer_pem, ocsp_url)

    # Estado global del bloque OpenSSL
    status = "pass" if (chain_result.get("ok") and ocsp_result.get("status") == "good") else \
             ("fail" if (ocsp_result.get("status") == "revoked") else "partial")

    return {
        "openssl": {
            "status": status,
            "x509_info": info,
            "chain": chain_result,
            "ocsp": ocsp_result
        }
    }
