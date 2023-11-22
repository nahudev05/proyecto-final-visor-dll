# Utiliza una imagen base de Python 
FROM python:3.11

# Establece el directorio de trabajo en /app
WORKDIR /app

# Copia los archivos necesarios al contenedor
COPY visor_dll.py .
COPY config.ini .
COPY help.txt .
COPY requirements.txt .
COPY ActionCenter.dll .

# Instala las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Configura el servidor X11 (utiliza la dirección IP del host para Windows)
# Asegúrate de tener VcXsrv u otro servidor X en ejecución en tu máquina host
ENV DISPLAY host.docker.internal:0

# Comando para ejecutar la aplicación
CMD ["python", "visor_dll.py"]
