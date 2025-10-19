import dns.resolver
from typing import List, Dict, Any

def _get_txt_all(name: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT")
        res = []
        for rdata in answers:
            # Unir fragmentos de TXT en una sola cadena
            res.append("".join([s.decode() for s in rdata.strings]))
        return res
    except Exception:
        return []

def _get_mx(name: str) -> List[Dict[str, Any]]:
    try:
        answers = dns.resolver.resolve(name, "MX")
        res = []
        for rdata in answers:
            res.append({
                "preference": int(rdata.preference),
                "exchange": str(rdata.exchange).rstrip(".")
            })
        return res
    except Exception:
        return []

def inspect_dns(domain: str) -> Dict[str, Any]:
    result = {
        "bimi": {
            "name": f"default._bimi.{domain}",
            "type": "TXT",
            "values": []
        },
        "dmarc": {
            "name": f"_dmarc.{domain}",
            "type": "TXT",
            "values": []
        },
        "mx": {
            "name": domain,
            "type": "MX",
            "values": []
        },
        "vmc_url_from_bimi": None
    }

    # BIMI TXT
    bimi_txts = _get_txt_all(result["bimi"]["name"])
    result["bimi"]["values"] = bimi_txts

    # DMARC TXT
    dmarc_txts = _get_txt_all(result["dmarc"]["name"])
    result["dmarc"]["values"] = dmarc_txts

    # MX
    result["mx"]["values"] = _get_mx(domain)

    # Extraer a= (URL VMC) si presente en BIMI
    vmc_url = None
    for raw in bimi_txts:
        for frag in raw.split(";"):
            frag = frag.strip()
            if frag.lower().startswith("a="):
                vmc_url = frag.split("=", 1)[1].strip()
                break
        if vmc_url:
            break
    result["vmc_url_from_bimi"] = vmc_url

    return result
