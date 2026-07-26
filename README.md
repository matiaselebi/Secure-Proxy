# SecureProxy

![CI](https://github.com/matiaselebi/secure-proxy/actions/workflows/ci.yml/badge.svg)

Proxy HTTP/HTTPS de filtrado con inteligencia de amenazas en tiempo real,
pensado como una capa de un stack personal de seguridad en profundidad
("defense in depth"): junto con [SecureDNS](https://github.com/matiaselebi/secure-dns)
(filtrado a nivel de resolución de nombres) y una futura VPN casera
(SecureVPN, transporte cifrado), cada proyecto cubre una capa distinta del
tráfico de red de una sola máquina, sin superponerse entre sí. Ver
"Limitaciones" más abajo para qué es y qué no es este proyecto.

Combina una lista negra de dominios (curada a mano y alimentada por feeds
públicos como URLhaus y OpenPhish), una lista de IPs de servidores de
comando-y-control de botnets (Feodo Tracker), reputación de IP vía
AbuseIPDB (con circuit breaker si la API falla, ver más abajo), y detección
de nodos de salida TOR. Las listas automáticas se actualizan solas en
segundo plano cada vez que arranca el proxy.

## Qué hace

- Actúa como **proxy directo (forward proxy)**: el cliente lo configura como
  salida a internet, y todo el tráfico HTTP/HTTPS pasa por él antes de llegar
  al destino.
- Soporta HTTP normal (GET/POST/etc.) y **HTTPS vía CONNECT** (túnel TCP, sin
  descifrar el contenido - el filtrado ocurre a nivel de dominio/IP, antes de
  abrir el túnel).
- Antes de dejar pasar una conexión, evalúa en orden:
  - **Lista blanca** (`data/allowlist.txt`): si el dominio está acá, se
    permite sin más chequeos - gana por sobre cualquiera de los siguientes.
  - Lista negra de dominios (`data/blocklist.txt`, curada a mano, combinada
    con `data/blocklist_feeds.txt`, generada automáticamente).
  - Lista de IPs de C2 de botnets conocidas (`data/ip_blocklist_feeds.txt`,
    generada automáticamente desde Feodo Tracker).
  - Si la IP de destino es un nodo de salida TOR conocido.
  - Reputación de la IP de destino contra la API de [AbuseIPDB](https://www.abuseipdb.com/)
    (con cache persistente en SQLite, ver más abajo).
- Cada conexión (permitida o bloqueada) queda registrada en SQLite, con la
  opción de enviar alertas por Telegram y de generar/ejecutar reglas de
  firewall (`iptables` en Linux, `netsh advfirewall` en Windows) para
  bloqueos persistentes.

## Contexto de seguridad

Este proxy filtra tráfico hacia dominios e IPs de reputación conocida como
maliciosa, pero **no aísla la ejecución de código**: si un sitio explota una
vulnerabilidad del navegador o induce la ejecución de un binario, el proxy no
ofrece protección contra eso. Para ese escenario, la recomendación es
complementarlo con aislamiento real (una máquina virtual o contenedor
desechable, idealmente con snapshots), usando el proxy como una capa
adicional que reduce la superficie de ataque bloqueando destinos de mala
reputación antes de que lleguen al navegador.

## Limitaciones

Documentar explícitamente qué NO hace este proyecto es, a propósito, parte
del diseño (evita dar una falsa sensación de cobertura total):

- **No descifra ni inspecciona TLS** (sin MITM): el filtrado de HTTPS es por
  dominio/IP antes de abrir el túnel CONNECT, nunca por contenido de la
  página. Ver [ADR 0001](docs/adr/0001-forward-proxy-no-tls-inspection.md)
  para la justificación de esta decisión (evitar instalar una CA raíz de
  confianza en el sistema).
- **No aísla la ejecución de código** (ver "Contexto de seguridad" arriba).
- **Depende de que la aplicación respete la configuración de proxy del
  sistema**: apps que gestionan su propia conexión de red por fuera de esa
  configuración simplemente no pasan por acá (ver "Alcance del filtrado por
  proxy del sistema" más abajo).
- **La reputación de IP vía AbuseIPDB es fail-open ante fallas**: si la API
  no responde (o está en cooldown por el circuit breaker, ver más abajo),
  esa capa específica de filtrado queda temporalmente inactiva; las demás
  (blocklist de dominios, IPs de C2, TOR) siguen funcionando igual. Ver
  [ADR 0002](docs/adr/0002-abuseipdb-fail-open-circuit-breaker.md).
- **Pensado para una sola máquina**, no para ser un gateway de red para
  varios dispositivos.
- **No reemplaza un antivirus ni una VPN**: es una capa de filtrado de
  destinos de red, complementaria a esas otras capas, no un sustituto.

## Estructura del proyecto

```
secure-proxy/
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
├── config/
│   └── config.yaml          # configuración del proxy
├── data/
│   ├── blocklist.txt        # lista negra de dominios (curada a mano)
│   └── allowlist.txt        # lista blanca de dominios (curada a mano o vía dashboard)
├── src/secureproxy/
│   ├── __init__.py
│   ├── config_loader.py     # carga config.yaml + variables de entorno
│   ├── logger_db.py         # logging estructurado en SQLite
│   ├── threat_intel.py      # AbuseIPDB + nodos TOR + blocklist + allowlist
│   ├── ip_reputation_cache.py  # cache persistente (SQLite) de scores de AbuseIPDB
│   ├── filter_engine.py     # decide permitir/bloquear una conexión
│   ├── notifier.py          # alertas por Telegram
│   ├── firewall_rules.py    # generación/ejecución de reglas de firewall
│   └── proxy_server.py      # servidor proxy HTTP/HTTPS (CONNECT)
├── scripts/
│   ├── run_proxy.py         # punto de entrada del proxy
│   ├── stop_proxy.py        # detiene el proxy por PID
│   └── update_blocklist.py  # descarga URLhaus + OpenPhish + Feodo Tracker
├── SecureProxy.bat          # panel de control para Windows
├── tests/
│   ├── test_filter_engine.py
│   ├── test_allowlist_and_cache.py
│   ├── test_logger_db.py
│   ├── test_proxy_integration.py
│   └── test_update_blocklist.py
├── docker/
│   └── Dockerfile
└── .github/workflows/ci.yml
```

## Instalación

### Linux / macOS

```bash
git clone https://github.com/matiaselebi/secure-proxy.git
cd secure-proxy
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # completar ABUSEIPDB_API_KEY (opcional; Telegram viene desactivado)
```

### Windows

```powershell
git clone https://github.com/matiaselebi/secure-proxy.git
cd secure-proxy
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

## Uso

En primer plano (logs visibles en consola, se detiene con Ctrl+C):

```bash
python scripts/run_proxy.py
```

En Windows, la forma más simple es usar el panel de control: doble clic en
`SecureProxy.bat` (ver la sección siguiente).

Por defecto levanta en `127.0.0.1:8888`. Para usarlo desde un navegador:

1. **Windows**: Configuración → Red e Internet → Proxy → activar "Usar un
   servidor proxy" con dirección `127.0.0.1` y puerto `8888`. Aplica a la
   mayoría de las apps de Windows, incluidos navegadores basados en
   Chromium. También puede lanzarse el navegador directo con el proxy sin
   tocar la configuración del sistema, por ejemplo:
   `brave.exe --proxy-server="127.0.0.1:8888"`.
2. **Linux**: Configuración → Sistema → proxy, o
   `brave-browser --proxy-server="127.0.0.1:8888"`.
3. Al navegar, si un dominio está en la blocklist o tiene mala reputación,
   la conexión se rechaza y queda registrada en `data/proxy_logs.db`.

Prueba rápida con curl, sin depender del navegador:

```bash
curl -x http://127.0.0.1:8888 http://example.com
curl -x http://127.0.0.1:8888 https://example.com   # prueba el túnel CONNECT
```

### Dashboard

Con el proxy corriendo, entrando directo (sin usarlo como proxy, solo como si
fuera una página cualquiera) a `http://127.0.0.1:8888/dashboard` se ve un
panel en vivo con el total de conexiones, la tasa de bloqueo, cuántas IPs
hay en el cache de AbuseIPDB, y tres pestañas: **Bloqueos** (los últimos
bloqueos, cada uno con un link "Permitir"), **Lista blanca** y **Lista
negra (manual)** — en estas dos últimas se puede agregar un dominio nuevo
con un formulario, o sacar uno existente con "Quitar", sin tocar ningún
archivo a mano. También hay un botón **"Borrar cache"** que vacía el cache
de reputación de IPs (en memoria y en disco). Se refresca solo cada 5
segundos, y recuerda qué pestaña tenías abierta entre refrescos.

Cada acción del dashboard (agregar/quitar de una lista, borrar cache)
cierra la conexión HTTP en vez de mantenerla abierta — esto evita el
cuelgue ocasional que podía pasar si el navegador dejaba la pestaña en
segundo plano y el refresco automático se demoraba más que el timeout del
socket.

### Panel de control en Windows (`SecureProxy.bat`)

Tras la instalación inicial (venv + `pip install`), la operación diaria se
hace con `SecureProxy.bat`, que ofrece un menú con 8 opciones:

1. **Iniciar proxy**: registra una tarea en el Programador de tareas de
   Windows para que el proxy arranque automáticamente en cada inicio de
   sesión (en segundo plano, sin ventana de consola, vía `pythonw.exe`), lo
   inicia de inmediato, y configura el proxy del sistema de Windows
   (`127.0.0.1:8888`) para que el navegador y la mayoría de las aplicaciones
   lo usen sin configuración adicional.
2. **Detener proxy**: elimina esa tarea programada, desactiva la
   configuración de proxy del sistema, y detiene el proceso si estaba
   corriendo.
3. **Ver estado**: informa si el inicio automático está activo, si el
   proceso está corriendo, si el proxy del sistema está habilitado, y
   cuántas entradas tiene el cache de AbuseIPDB ahora mismo (leyendo
   directo el archivo SQLite, funciona esté o no corriendo el proxy).
4. **Actualizar listas de amenazas**: fuerza la descarga inmediata de
   URLhaus, OpenPhish y Feodo Tracker, y regenera `data/blocklist_feeds.txt`
   y `data/ip_blocklist_feeds.txt`. El proxy también lo hace solo, en segundo
   plano, cada vez que arranca (ver la sección siguiente); esta opción sirve
   para forzarlo en el momento sin esperar.
5. **Agregar dominio a la lista blanca**: pide el dominio por teclado y lo
   agrega a `data/allowlist.txt`. Si el proxy está corriendo, se aplica solo
   en unos segundos (hay un hilo en segundo plano que recarga las listas
   cada 15 segundos, sin necesidad de reiniciar el proceso).
6. **Agregar dominio a la lista negra**: igual que la anterior, pero a
   `data/blocklist.txt` (la lista manual).
7. **Borrar cache de reputación de IPs**: si el proxy está corriendo, lo
   vacía al instante llamando al mismo endpoint que usa el botón del
   dashboard. Si no está corriendo, avisa que no hay nada para borrar en
   caliente (el cache en disco sigue ahí, pero las entradas vencen solas).
8. **Salir**: cierra el menú sin realizar cambios.

Mientras no se elija la opción 2, el proxy sigue arrancando automáticamente
en cada inicio de sesión, incluso si se cierra el menú o se reinicia el
equipo.

## Historial de bloqueos

El historial que se ve en la pestaña "Bloqueos" del dashboard es
**acumulado desde la primera vez que corriste el proxy**, no solo desde el
último arranque: cada conexión (permitida o bloqueada) se guarda en
`data/proxy_logs.db` (SQLite), un archivo que persiste en disco entre
reinicios. El dashboard siempre muestra los últimos 25 bloqueos de esa
base completa, ordenados del más reciente al más viejo.

Si una conexión que esperabas ver bloqueada no aparece ahí, lo más probable
es una de estas dos cosas, no un problema del historial en sí:

- La aplicación que la generó no pasó en absoluto por el proxy (por
  ejemplo, algunas apps de escritorio no respetan la configuración de
  proxy del sistema, o usan su propia configuración de red separada — ver
  "Alcance del filtrado por proxy del sistema" más abajo).
- El proxy dejó pasar la conexión sin marcarla como bloqueada (por
  ejemplo, si el dominio de destino no estaba en ninguna de las listas ni
  tenía mala reputación en ese momento).

Para confirmar rápido si algo pasó o no por el proxy, la forma más directa
es mirar el total de "Conexiones totales" del dashboard (cuenta todo, no
solo lo bloqueado) mientras reproducís el caso.

## Alcance del filtrado por proxy del sistema

Al configurar el proxy a nivel de sistema (opción 1 del panel), la
configuración se aplica en `Internet Settings` de Windows, la misma que usan
Chrome, Edge y la mayoría de las aplicaciones de escritorio que respetan la
configuración de red del sistema operativo. Esto extiende el filtrado más
allá del navegador a cualquier aplicación que use esa configuración.

Es importante ser preciso sobre el alcance real: el proxy únicamente
inspecciona el tráfico de red que decide enrutar a través de él. No accede,
escanea ni modifica archivos en disco. Aplicaciones que gestionan su propia
conexión de red por fuera de la configuración del sistema (algo común en
ciertos launchers de terceros) simplemente no pasan por este filtro.

## Listas de amenazas automáticas (URLhaus + OpenPhish + Feodo Tracker)

`data/blocklist.txt` es la lista curada a mano (para agregar dominios
puntuales). `data/blocklist_feeds.txt` y `data/ip_blocklist_feeds.txt` se
generan automáticamente ejecutando `python scripts/update_blocklist.py` (o
la opción 4 del panel), combinando tres fuentes públicas y gratuitas:

- **URLhaus** (abuse.ch): dominios que distribuyen malware activamente.
- **OpenPhish**: dominios usados en campañas de phishing activas.
- **Feodo Tracker** (abuse.ch): IPs de servidores de comando-y-control (C2)
  de botnets conocidas (Dridex, Emotet, TrickBot, QakBot, etc).

El proxy carga estos archivos automáticamente en cada arranque, y además
verifica en un hilo en segundo plano si conviene refrescarlos - sin
bloquear el inicio del servidor. Si la última actualización tiene más de
`filtering.feeds_update_interval_hours` (6 horas por defecto), descarga la
versión nueva y recarga las listas en caliente, sin necesidad de reiniciar
el proceso. Si la última actualización es reciente, se omite la descarga
para no consultar los feeds de más. La opción 4 del panel (o correr
`update_blocklist.py` directo) siempre fuerza la descarga, ignorando ese
intervalo.

## Configuración (`config/config.yaml`)

- `proxy.host` / `proxy.port`: dirección y puerto donde escucha el proxy.
- `filtering.blocklist_path`: archivo de dominios bloqueados a mano.
- `filtering.feeds_blocklist_path`: dominios generados por `update_blocklist.py`.
- `filtering.ip_feeds_blocklist_path`: IPs de C2 generadas por `update_blocklist.py`.
- `filtering.allowlist_path`: archivo de dominios permitidos a mano (o vía el
  botón "Permitir" del dashboard). Gana por sobre blocklist, TOR y AbuseIPDB.
- `filtering.feeds_update_interval_hours`: horas mínimas entre actualizaciones
  automáticas de las listas al arrancar (default 6).
- `filtering.abuseipdb_min_score`: score de 0 a 100 a partir del cual se
  bloquea una IP (default 50).
- `filtering.abuseipdb_cache_ttl`: segundos que se considera válido un score
  cacheado (en memoria y en disco) antes de volver a consultar la API.
- `filtering.abuseipdb_cache_db_path`: archivo SQLite donde se persiste el
  cache de AbuseIPDB entre reinicios del proxy (no se pierde al reiniciar,
  a diferencia del cache en memoria).
- `filtering.check_tor_exit_nodes`: si bloquea salidas hacia nodos TOR
  conocidos.
- `filtering.mode`: `"enforce"` (default, bloquea de verdad) o `"audit"`
  (evalúa y registra qué se hubiera bloqueado, pero deja pasar todo el
  tráfico - pensado para probar una lista o umbral nuevo sin riesgo antes
  de aplicarlo en serio; ver [ADR 0003](docs/adr/0003-audit-mode.md)).
- `firewall.enabled`: si además de loguear, ejecuta reglas de firewall reales
  (por defecto `false` - modo dry-run, solo genera el comando).
- `telegram.enabled`: si envía alertas por Telegram (opcional, desactivado
  por defecto).

## Resiliencia ante fallas de AbuseIPDB (circuit breaker)

Si la consulta a AbuseIPDB falla 3 veces seguidas (`AbuseIPDBClient.
FAILURE_THRESHOLD`), el cliente deja de intentar la llamada de red durante
60 segundos (`RESET_TIMEOUT_SECONDS`) y devuelve score 0 de inmediato en
ese período, en vez de pagar el timeout completo (5s) en cada conexión
nueva mientras el servicio está caído. Pasado ese tiempo, la próxima
consulta se intenta de nuevo con normalidad; si funciona, el circuito se
cierra solo. Detalle y justificación en
[ADR 0002](docs/adr/0002-abuseipdb-fail-open-circuit-breaker.md).

## Validación de dominios en el dashboard

Los formularios de "Lista blanca" y "Lista negra" del dashboard (y las
opciones equivalentes del menú .bat) validan que el texto ingresado tenga
forma de dominio o IP antes de escribirlo en el archivo de lista
correspondiente (`src/secureproxy/validation.py`). Esto evita que una URL
completa pegada por error ("http://ejemplo.com/ruta") termine guardada tal
cual en `data/allowlist.txt` o `data/blocklist.txt`, donde no matchearía
nunca contra un hostname real.

## Tests

```bash
pytest tests/ -v
```

Cobertura actual: motor de filtrado (blocklist, allowlist, AbuseIPDB, nodos
TOR, Feodo Tracker, modo audit), circuit breaker de AbuseIPDB (apertura,
cierre, y que un fallo aislado no lo dispara), validación de formato de
dominio, cache persistente de reputación de IPs, logging en SQLite,
integración end-to-end del servidor proxy (tráfico permitido, bloqueado, el
flujo completo de "Permitir" desde el dashboard, y el rechazo de dominios
mal formados), y parseo de los feeds de amenazas.

## Docker

```bash
docker build -t secure-proxy -f docker/Dockerfile .
docker run -p 8888:8888 --env-file .env secure-proxy
```

## Decisiones de diseño (ADRs)

Las decisiones de arquitectura no triviales (por qué no se hace inspección
TLS, por qué AbuseIPDB es fail-open con circuit breaker, por qué existe un
modo audit) están documentadas en `docs/adr/`, con su contexto y las
consecuencias aceptadas de cada una - para que quede registro del "por qué"
además del "qué".

Las dependencias (`requirements.txt` y las Actions del CI) se mantienen
actualizadas automáticamente vía Dependabot (`.github/dependabot.yml`,
chequeo semanal).

## Roadmap

- Endpoint de métricas estilo Prometheus (`/metrics`).
- Soporte de reglas por expresión regular además de dominios exactos.
- Integración con SecureDNS y una futura VPN casera (WireGuard) en un
  repositorio unificado.

## Aviso

Proyecto educativo/de portfolio. No debe usarse como única defensa contra
amenazas reales: se recomienda combinarlo con aislamiento real (VM o
contenedores), una solución antivirus, y buenas prácticas de navegación.

## Autor

Matias Elebi - [LinkedIn](https://linkedin.com/in/matiaselebi/) · [GitHub](https://github.com/matiaselebi)

## Licencia

MIT
