FROM python:3.11-slim

# Instalamos dependencias necesarias para OpenSSL y validaciones de red
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Definimos directorio de trabajo
WORKDIR /app

# Copiamos requirements e instalamos dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el código fuente
COPY src ./src

# Variables de entorno
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Exponemos el puerto
EXPOSE 8080

# Comando de arranque
CMD ["python", "-m", "src.main"]
