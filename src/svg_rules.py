import requests
from lxml import etree
from urllib.parse import urlparse
import os
import hashlib

TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "15"))
DEFAULT_HEADERS = {
    "User-Agent": "BIMI-VMC-Validator/1.0 (+https://example.com)",
    "Accept": "image/svg+xml,*/*"
}

def svg_sha256(svg_bytes: bytes) -> str:
    return hashlib.sha256(svg_bytes).hexdigest()

def check_svg(svg_url: str) -> dict:
    out = {"exists": False, "compliant": False, "size_bytes": None, "sha256": None}
    parsed = urlparse(svg_url)
    if parsed.scheme != "https":
        out["message"] = "El logo debe servirse por HTTPS"
        return out
    try:
        r = requests.get(svg_url, timeout=TIMEOUT, headers=DEFAULT_HEADERS, allow_redirects=True)
        r.raise_for_status()
        content = r.content
        out["exists"] = True
        out["size_bytes"] = len(content)
        out["sha256"] = svg_sha256(content)
        if len(content) > 300000:
            out["message"] = "SVG demasiado grande (>300KB)"
            return out
        parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
        root = etree.fromstring(content, parser=parser)
        disallow_tags = {"script", "foreignObject", "image"}
        for tag in disallow_tags:
            if root.findall(".//" + tag):
                out["message"] = f"Etiqueta no permitida: {tag}"
                return out
        for style in root.findall(".//style"):
            if style.text and "url(" in style.text:
                out["message"] = "Estilos con url() no permitidos"
                return out
        if "viewBox" not in root.attrib:
            out["message"] = "Falta atributo viewBox en SVG"
            return out
        out["compliant"] = True
        out["message"] = "SVG conforme a reglas BIMI-safe"
        return out
    except Exception as e:
        out["message"] = f"Error al obtener/parsing SVG: {e}"
        return out
