Coloque aquí las claves RSA.
Generar en local:
  openssl genpkey -algorithm RSA -out keys/private.pem -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout -in keys/private.pem -out keys/public.pem

El proyecto intenta usar keys/private.pem para firmar JWT y PDF. Si no existen, el servidor usa modo desarrollo (HS256) para JWT.
