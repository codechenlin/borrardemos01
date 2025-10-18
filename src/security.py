import os
from functools import wraps
from flask import request, jsonify

ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        expected_key = os.environ.get("API_KEY", "").strip()
        provided_key = request.headers.get("X-API-KEY", "").strip()

        if not expected_key:
            return jsonify({"error": "API_KEY no está configurada en el servidor"}), 500

        if provided_key != expected_key:
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return decorated

def cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-KEY"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    return resp
