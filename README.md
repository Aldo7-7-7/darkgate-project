# DarkGate Access Control - Proyecto Integrador (Esqueleto)

Nombre del proyecto: DarkGate Access Control

Instrucciones rápidas para ejecutar localmente:

1. Crear y activar entorno virtual:
   - Windows:
     ```
     python -m venv venv
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```
     python -m venv venv
     source venv/bin/activate
     ```

2. Instalar dependencias:
```
pip install -r requirements.txt
```

3. Generar claves RSA en `keys/` (ver instrucciones en este README) o copiar las suyas:
```
mkdir keys
openssl genpkey -algorithm RSA -out keys/private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/private.pem -out keys/public.pem
```

4. Copiar `.env.example` a `.env` y completar valores (RECAPTCHA, MAIL, SECRET_KEY).

5. Inicializar base de datos:
```
python models.py
```

6. Ejecutar la aplicación:
```
set FLASK_APP=app.py        # Windows
export FLASK_APP=app.py     # Linux/Mac
flask run --cert=adhoc
```

Acceder en: https://127.0.0.1:5000/

**Notas:** reCAPTCHA requiere claves reales; para pruebas puede comentar la verificación temporalmente. 
