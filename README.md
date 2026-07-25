# SecureProxy

Proxy HTTP/HTTPS de filtrado con inteligencia de amenazas en tiempo real,
pensado como capa de seguridad adicional para la navegación. Combina una
lista negra de dominios (curada a mano y alimentada por feeds públicos como
URLhaus y OpenPhish) con reputación de IP vía AbuseIPDB y detección de nodos
de salida TOR.

## Qué hace

- Actúa como **proxy directo (forward proxy)**: el cliente lo configura como
  salida a internet, y todo el tráfico HTTP/HTTPS pasa por él antes de llegar
  al destino.
- Soporta HTTP normal (GET/POST/etc.) y **HTTPS vía CONNECT** (túnel TCP, sin
  descifrar el contenido — el filtrado ocurre a nivel de dominio/IP, antes de
  abrir el túnel).
- Antes de dejar pasar una conexión, evalúa:
  - Lista negra de dominios (`data/blocklist.txt`, curada a mano, combinada
    con `data/blocklist_feeds.txt`, generada automáticamente).
  - Reputación de la IP de destino contra la API de [AbuseIPDB](https://www.abuseipdb.com/).
  - Si la IP de destino es un nodo de salida TOR conocido.
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
│   └── blocklist.txt        # lista negra de dominios (curada a mano)
├── src/secureproxy/
│   ├── __init__.py
│   ├── config_loader.py     # carga config.yaml + variables de entorno
│   ├── logger_db.py         # logging estructurado en SQLite
│   ├── threat_intel.py      # AbuseIPDB + nodos TOR + blocklist
│   ├── filter_engine.py     # decide permitir/bloquear una conexión
│   ├── notifier.py          # alertas por Telegram
│   ├── firewall_rules.py    # generación/ejecución de reglas de firewall
│   └── proxy_server.py      # servidor proxy HTTP/HTTPS (CONNECT)
├── scripts/
│   ├── run_proxy.py         # punto de entrada del proxy
│   ├── stop_proxy.py        # detiene el proxy por PID
│   └── update_blocklist.py  # descarga URLhaus + OpenPhish
├── SecureProxy.bat          # panel de control para Windows
├── tests/
│   ├── test_filter_engine.py
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
git clone https://github.com/<usuario>/secure-proxy.git
cd secure-proxy
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # completar ABUSEIPDB_API_KEY (opcional; Telegram viene desactivado)
```

### Windows

```powershell
git clone https://github.com/<usuario>/secure-proxy.git
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

### Panel de control en Windows (`SecureProxy.bat`)

Tras la instalación inicial (venv + `pip install`), la operación diaria se
hace con `SecureProxy.bat`, que ofrece un menú con 5 opciones:

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
   proceso está corriendo, y si el proxy del sistema está habilitado.
4. **Actualizar listas de amenazas**: descarga los feeds de URLhaus y
   OpenPhish y regenera `data/blocklist_feeds.txt`.
5. **Salir**: cierra el menú sin realizar cambios.

Mientras no se elija la opción 2, el proxy sigue arrancando automáticamente
en cada inicio de sesión, incluso si se cierra el menú o se reinicia el
equipo.

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

## Listas de amenazas automáticas (URLhaus + OpenPhish)

`data/blocklist.txt` es la lista curada a mano (para agregar dominios
puntuales). `data/blocklist_feeds.txt` se genera automáticamente ejecutando
`python scripts/update_blocklist.py` (o la opción 4 del panel), combinando
dos fuentes públicas y gratuitas:

- **URLhaus** (abuse.ch): dominios que distribuyen malware activamente.
- **OpenPhish**: dominios usados en campañas de phishing activas.

El proxy carga ambos archivos en conjunto en cada arranque. Si el proxy ya
estaba corriendo, conviene reiniciarlo tras un update para que tome la lista
nueva. La actualización no es continua: cada ejecución del script refleja el
estado de esos feeds en ese momento.

## Configuración (`config/config.yaml`)

- `proxy.host` / `proxy.port`: dirección y puerto donde escucha el proxy.
- `filtering.blocklist_path`: archivo de dominios bloqueados a mano.
- `filtering.feeds_blocklist_path`: archivo generado por `update_blocklist.py`.
- `filtering.abuseipdb_min_score`: score de 0 a 100 a partir del cual se
  bloquea una IP (default 50).
- `filtering.check_tor_exit_nodes`: si bloquea salidas hacia nodos TOR
  conocidos.
- `firewall.enabled`: si además de loguear, ejecuta reglas de firewall reales
  (por defecto `false` — modo dry-run, solo genera el comando).
- `telegram.enabled`: si envía alertas por Telegram (opcional, desactivado
  por defecto).

## Tests

```bash
pytest tests/ -v
```

Cobertura actual: motor de filtrado (blocklist, AbuseIPDB, nodos TOR),
logging en SQLite, integración end-to-end del servidor proxy (tráfico
permitido y bloqueado), y parseo de los feeds de amenazas.

## Docker

```bash
docker build -t secure-proxy -f docker/Dockerfile .
docker run -p 8888:8888 --env-file .env secure-proxy
```

## Roadmap

- Cache persistente de reputación de IPs (actualmente en memoria).
- Dashboard web para visualizar bloqueos en tiempo real.
- Endpoint de métricas estilo Prometheus (`/metrics`).
- Soporte de reglas por expresión regular además de dominios exactos.

## Aviso

Proyecto educativo/de portfolio. No debe usarse como única defensa contra
amenazas reales: se recomienda combinarlo con aislamiento real (VM o
contenedores), una solución antivirus, y buenas prácticas de navegación.

## Autor

Matias Yamil Elebi — [LinkedIn](#) · [GitHub](#)

## Licencia

MIT
