from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json

def sign_log(log_data: dict, private_key_path: str) -> dict:
    try:
        log_bytes = json.dumps(log_data, indent=2).encode("utf-8")
        private_key = serialization.load_pem_private_key(
            open(private_key_path, "rb").read(),
            password=None
        )
        signature = private_key.sign(
            log_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return {
            "log": log_data,
            "signature": signature.hex()
        }
    except Exception as e:
        return {
            "error": f"Error al firmar log: {e}"
        }
