# ADR 0001: Proxy directo (forward proxy) sin inspección TLS

## Estado

Aceptado.

## Contexto

SecureProxy necesita filtrar tráfico HTTPS sin poder ver, en principio, qué
dominio o URL exacta se está pidiendo dentro del túnel cifrado. Existen dos
enfoques posibles: (a) dejar el túnel TLS intacto (CONNECT sin descifrar) y
filtrar solo por el nombre de host visible antes de abrirlo, o (b) hacer
inspección TLS (MITM): generar un certificado propio al vuelo, instalar una
CA raíz de confianza en el sistema, y descifrar/re-cifrar el tráfico para
poder filtrar por contenido, no solo por dominio.

## Decisión

Se implementó la opción (a): CONNECT sin descifrar. El filtrado ocurre
antes de abrir el túnel, usando el hostname que ya viaja en texto plano en
el propio pedido CONNECT (y, para HTTPS, adicionalmente disponible vía SNI
si hiciera falta en el futuro).

## Consecuencias

Ventajas: no requiere instalar una CA raíz de confianza en el sistema (un
paso que además de ser invasivo, si la clave privada de esa CA se filtrara,
comprometería la confianza TLS de toda la máquina); no rompe HSTS ni
certificate pinning de las apps; menor superficie de ataque en el propio
proxy (no maneja certificados de terceros ni claves privadas de sitios).

Limitación aceptada conscientemente: el filtrado es por dominio/IP, no por
URL completa ni por contenido de la página. Un dominio permitido que sirve
contenido malicioso en una ruta específica no se detecta por este medio. Es
una limitación documentada en el README ("Contexto de seguridad"), no un
descuido.
