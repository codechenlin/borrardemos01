# API BIMI+VMC con verificación PKI avanzada, auditoría y extracción DNS

Valida BIMI (DNS/DMARC), seguridad del SVG y VMC con:
- Cadena hasta el emisor (AIA CA Issuers).
- Revocación por OCSP (fallback CRL).
- Señales de hash de logo si el VMC lo expone.
- Logs con retención automática.
- **Extracción DNS**: BIMI TXT (name/type/values), DMARC TXT (name/type/values), MX (host/prioridad), y `a=` (URL VMC) desde BIMI.

## Endpoints

### GET /health
Respuesta: `{ "status": "ok" }`

### GET /validate?domain=<dominio>
Headers: `X-API-KEY: <tu_api_key>`
Respuesta JSON:
- `dns`:
  - `bimi`: `{ name, type: "TXT", values: [ ... ] }`
  - `dmarc`: `{ name, type: "TXT", values: [ ... ] }`
  - `mx`: `{ name, type: "MX", values: [ { preference, exchange } ] }`
  - `vmc_url_from_bimi`: URL si está presente en BIMI `a=`
- `bimi`: existencia/sintaxis + estado DMARC
- `svg`: cumplimiento BIMI-safe, tamaño, sha256
- `vmc`: autenticidad, cadena, revocación, detalles OCSP/CRL, hash de logo, `source_url`
- `status`: `pass`, `pass_without_vmc`, `indeterminate_revocation`, `fail`
- `recommendations`: acciones sugeridas

## Mensajes VMC más claros
- Sin `a=` en BIMI: `"El dominio no incluye VMC (no hay campo a= en el registro BIMI)"`
- URL VMC inaccesible: `"No se pudo descargar el VMC desde la URL indicada (...)"` con detalle (HTTP, timeout, red).
- OCSP/CRL indisponibles: `ocsp_detail`/`crl_detail` y `retry_suggestion`.

## Interpretación de estados
- `pass`: BIMI+SVG correctos y VMC autenticado (cadena + revocación + vigencia).
- `pass_without_vmc`: BIMI+SVG correctos; no hay VMC.
- `indeterminate_revocation`: VMC presente pero OCSP/CRL indisponibles → reintentos.
- `fail`: fallos en BIMI/SVG/VMC (ver `message`).

## Prevención de falsos resultados
- Tratar `revocation_ok=null` como “indeterminado” y reintentar según `retry_suggestion`.
- Si `vmc_logo_hash_present=false`, no es error: la CA puede no incluir hash.
- Si `vmc` indica URL inaccesible, es una condición real del dominio, no un bug del sistema.

