# ADR 0004: País, ASN y proveedor con una base LOCAL en SQLite

## Estado

Aceptado.

## Contexto

Para que el historial sirva para investigar (por ejemplo, "qué le mandé a un
servidor en Rusia", o "qué proveedor está detrás de esta IP") hace falta
guardar, además del dominio, el país, el sistema autónomo (ASN) y el
proveedor de la IP de destino.

Hay dos formas obvias de conseguir esos datos, y las dos tienen un problema:

- **Una API por conexión** (ipinfo, ip-api y similares). El proxy ve TODO el
  tráfico de la máquina. A diez conexiones por segundo, esto es una llamada
  de red por cada una: destruye el rendimiento del proxy, quema el cupo
  gratuito en minutos, y encima le cuenta a un tercero cada sitio que visita
  el usuario.
- **El formato `.mmdb` de MaxMind**. Es el estándar de hecho, pero leerlo a
  mano no es razonable, y usar el lector oficial significa una dependencia
  nueva en un proyecto que hasta acá resuelve casi todo con la librería
  estándar.

## Decisión

Base local en SQLite, armada desde los CSV lite de DB-IP, que se publican
gratis, sin cuenta, una vez por mes y bajo licencia CC-BY.

`scripts/update_geoip.py` baja los dos CSV (países y ASN), los cruza por
rango, convierte cada rango a un par de enteros y los inserta en
`data/geoip.db` con un índice por el inicio del rango. Con eso, resolver una
IP es una búsqueda por índice, no un recorrido. Encima hay un cache en
memoria de las últimas 4096 resoluciones, porque un navegador vuelve una y
otra vez a las mismas IPs.

La descarga es explícita: la corre el usuario, o la opción 8 del panel de
Windows. El proxy nunca la baja solo durante el tráfico, a propósito, porque
son varios megabytes.

## Consecuencias

Ninguna consulta de red durante el tráfico, ninguna dependencia nueva, y la
base queda inspeccionable con cualquier visor de SQLite.

Los datos son un poco menos precisos que los de una base paga y se
desactualizan entre descargas, lo cual está bien: son contexto del registro,
no participan de la decisión de bloquear.

Si la base no está descargada, `GeoIP.disponible` es `False`, esas columnas
quedan vacías y el proxy funciona exactamente igual. Eso es deliberado: una
funcionalidad de contexto no puede ser capaz de romper el camino del
tráfico.
