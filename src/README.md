# API BIMI+VMC con verificación PKI avanzada y auditoría

Valida BIMI (DNS/DMARC), seguridad del SVG y VMC con:
- Cadena hasta el emisor (AIA CA Issuers).
- Revocación por OCSP (fallback CRL).
- Señales de hash de logo si el VMC lo expone.
- Logs con retención automática.

## Despliegue en Coolify

1. Crea un repositorio público en GitHub con estos archivos.
2. En Coolify, crea una app desde GitHub, puerto interno 8080.
3. Variables de entorno (.env):
   - `API_KEY`: tu clave secreta.
   - `ALLOWED_ORIGIN`: tu dominio público (ej. https://8b3i4m6i39303g2k432u.fanton.cloud).
   - `RETENTION_DAYS`: días de retención de logs (default 2).
4. Asigna dominio y HTTPS. Despliega.

## Seguridad

- Autenticación por encabezado `X-API-KEY`.
- CORS limitado a `ALLOWED_ORIGIN`.
- Todo tráfico por HTTPS.

## Endpoints

### GET /health
Simple verificación de estado.
- Respuesta: `{ "status": "ok" }`

### GET /validate?domain=<dominio>
Realiza la validación completa.
- Headers: `X-API-KEY: <tu_api_key>`
- Respuesta JSON:
  - `bimi`: existencia y sintaxis de TXT, estado DMARC.
  - `svg`: cumplimiento BIMI-safe, tamaño, sha256.
  - `vmc`: autenticidad, cadena, revocación, OCSP/CRL con detalles, hash de logo.
  - `status`: `pass`, `pass_without_vmc`, `indeterminate_revocation`, `fail`.
  - `recommendations`: sugerencias de acción (reintentos, ajustes SVG/DMARC/cadena).

### GET /logs?domain=<dominio>&days=<n>
Consulta logs recientes (historial).
- Headers: `X-API-KEY: <tu_api_key>`
- Parámetros:
  - `domain` (opcional): filtra por dominio.
  - `days` (opcional): días atrás (default `RETENTION_DAYS`).
- Respuesta:
```json
{
  "count": 2,
  "logs": [
    { "domain": "midominio.com", "created_at": "2025-10-17T14:22:01Z", "report": { ... } }
  ]
}
