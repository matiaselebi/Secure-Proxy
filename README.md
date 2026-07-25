# SecureProxy

Proxy HTTP/HTTPS de filtrado con inteligencia de amenazas, pensado como capa de
seguridad para navegación (Brave, curl, o cualquier cliente que soporte proxy)
corriendo dentro de una máquina virtual aislada (por ejemplo Kali Linux).

## ¿Qué hace?

- Actúa como **proxy directo (forward proxy)**: el cliente lo configura como su
  salida a internet, y todo el tráfico HTTP/HTTPS pasa por acá antes de llegar
  al destino.
- Soporta HTTP normal (GET/POST/etc.) y **HTTPS vía CONNECT** (túnel TCP, sin
  descifrar el contenido — solo filtra por dominio/IP antes de abrir el túnel).
- Antes de dejar pasar una conexión, chequea:
  - Lista negra local de dominios (`data/blocklist.txt`).
  - Reputación de la IP de destino contra la API de [AbuseIPDB](https://www.abuseipdb.com/).
  - Si la IP de destino es un nodo de salida TOR conocido.
- Si bloquea algo, lo registra en SQLite, opcionalmente manda una alerta por
  Telegram, y opcionalmente genera (o ejecuta) una regla `iptables` para
  bloquear esa IP a nivel de sistema.

## Por qué existe (contexto de seguridad importante)

Este proxy **filtra tráfico conocido como malicioso**, pero **no aísla
ejecución de código**. Si un sitio explota una vulnerabilidad del navegador o
te hace ejecutar un binario, el proxy no te protege de eso. Para eso la
recomendación es correr el navegador dentro de una VM (o un contenedor)
desechable con snapshots, y usar este proxy como una capa adicional que reduce
la superficie de ataque bloqueando dominios e IPs de mala reputación antes de
que el navegador llegue a cargarlos.

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
│   └── blocklist.txt        # lista negra de dominios
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
├── SecureProxy.bat          # menú de control para Windows (iniciar/detener/estado/actualizar)
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

### Linux / macOS / Kali

```bash
git clone <tu-repo>
cd secure-proxy
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # completá tu ABUSEIPDB_API_KEY (opcional; Telegram es opcional y viene desactivado)
```

### Windows

```powershell
git clone <tu-repo>
cd secure-proxy
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

## Uso

En primer plano (ves los logs en vivo, se corta con Ctrl+C):

```bash
python scripts/run_proxy.py
```

En Windows, la forma más simple es usar el panel de control: hacé doble clic
en `SecureProxy.bat` (ver la sección siguiente).

Por defecto levanta en `127.0.0.1:8888`. Para usarlo desde Brave:

1. **Windows**: Configuración de Windows → Red e Internet → Proxy → activar
   "Usar un servidor proxy" con dirección `127.0.0.1` y puerto `8888`. Esto
   aplica a Brave y a la mayoría de las apps de Windows. También podés lanzar
   Brave directo con el proxy sin tocar la config del sistema:
   `brave.exe --proxy-server="127.0.0.1:8888"`.
2. **Linux/Kali**: Configuración → Sistema → proxy, o
   `brave-browser --proxy-server="127.0.0.1:8888"`.
3. Navegá normal. Si un dominio está en la blocklist o tiene mala reputación,
   vas a ver un error de conexión rechazada y quedará registrado en
   `data/proxy_logs.db`.

Para probarlo rápido con curl, sin tocar el navegador (funciona igual en
Windows con PowerShell o `cmd`, si tenés curl instalado — viene incluido
desde Windows 10):

```bash
curl -x http://127.0.0.1:8888 http://example.com
curl -x http://127.0.0.1:8888 https://example.com   # prueba el túnel CONNECT
```

### Panel de control en Windows (`SecureProxy.bat`)

Una vez que hiciste la instalación inicial (venv + `pip install`), no volvés
a tocar la consola: doble clic en `SecureProxy.bat` te muestra un menú de
texto con 5 opciones.

**1. Iniciar proxy** hace tres cosas: registra una tarea en el Programador de
tareas de Windows para que el proxy arranque solo cada vez que iniciás sesión
(oculto, sin ventana de consola, usando `pythonw.exe`), lo arranca ahora
mismo sin esperar a que reinicies, y configura el proxy del sistema de
Windows (`127.0.0.1:8888`) para que Brave y la mayoría de las apps lo usen
automáticamente sin que tengas que tocar la configuración de cada una.

**2. Detener proxy** hace lo inverso: borra esa tarea programada (así no
vuelve a arrancar solo la próxima vez que prendas la PC), apaga la
configuración de proxy del sistema, y mata el proceso si estaba corriendo en
ese momento.

**3. Ver estado** te dice, sin ambigüedad, si el inicio automático está
activado, si el proceso está corriendo, y si el proxy del sistema está
activo — útil para no quedarte con la duda de en qué quedó todo.

**4. Actualizar listas de amenazas** descarga los feeds de URLhaus y
OpenPhish y regenera `data/blocklist_feeds.txt` (ver la sección siguiente).

**5. Salir** cierra el menú sin tocar nada.

Importante: mientras no elijas la opción 2, el proxy va a seguir
arrancando solo cada vez que prendas la PC e inicies sesión, aunque cierres
el menú o reinicies. Es la opción 2 la que lo apaga *y* evita que vuelva a
prenderse solo.

### Aviso sobre correrlo en tu Windows "normal" (sin VM)

Este proxy filtra dominios/IPs de mala reputación, pero **no aísla la
ejecución de código**. Si lo corrés directo en tu Windows de uso diario (sin
una VM de por medio), seguís teniendo la protección de "no me conecto a
sitios conocidos como maliciosos", pero no la protección de "si un sitio
explota una vulnerabilidad del navegador, no puede tocar mi PC" — para eso
seguís necesitando aislamiento real (VM, contenedor, etc.). Ambas cosas son
válidas y complementarias, pero no son lo mismo.

## Listas de amenazas automáticas (URLhaus + OpenPhish)

`data/blocklist.txt` es tu lista manual (para agregar dominios puntuales a
mano). `data/blocklist_feeds.txt` es una lista aparte que se genera sola
corriendo `python scripts/update_blocklist.py` (o la opción 4 del menú), y
combina dos fuentes públicas y gratuitas:

- **URLhaus** (abuse.ch): dominios que están repartiendo malware activamente
  en este momento.
- **OpenPhish**: dominios usados en campañas de phishing activas.

El proxy lee ambos archivos juntos automáticamente cada vez que arranca. No
hace falta reiniciar el proxy después de correr el update, salvo que ya
estuviera corriendo (ahí sí conviene reiniciarlo desde el menú para que tome
la lista nueva). Esta lista no se actualiza sola de forma continua: cada vez
que la corras vas a tener la versión más reciente de esos feeds en ese
momento.

## Proxy a nivel de todo el sistema, y una aclaración sobre archivos locales

Cuando usás la opción 1 del menú, no solo se configura Brave: se cambia la
configuración de proxy de Windows a nivel de sistema (`Internet Settings` de
Windows), que es la misma que usan Chrome, Edge, y la mayoría de las
aplicaciones de escritorio que respetan la configuración de red del sistema
operativo. Eso significa que, además de tu navegador, cualquier otro programa
que use esa configuración también va a pasar su tráfico por el filtro.

Dicho esto, es importante ser preciso sobre qué significa esto en la
práctica: el proxy **solo mira tráfico de red que decide pasar por él**. No
escanea, no indexa, no toca ni puede borrar ningún archivo de tu disco —no
tiene ni una línea de código para eso. Si tenés juegos pirateados, cracks, o
lo que sea guardado localmente, el proxy no los va a tocar bajo ninguna
circunstancia. Lo único que podría pasar es lo contrario: muchos
launchers/cracks usan su propia conexión de red por fuera de la
configuración de proxy de Windows, así que es bastante probable que ni
siquiera pasen por el filtro y sigan funcionando exactamente igual que
antes, para bien (no se rompen) y para mal (no quedan protegidos por esta
capa en particular).

## Configuración (`config/config.yaml`)

- `proxy.host` / `proxy.port`: dónde escucha el proxy.
- `filtering.blocklist_path`: archivo de dominios bloqueados a mano (uno por línea).
- `filtering.feeds_blocklist_path`: archivo generado por `update_blocklist.py` (URLhaus + OpenPhish).
- `filtering.abuseipdb_min_score`: score de 0 a 100 a partir del cual se
  bloquea una IP (default 50).
- `filtering.check_tor_nodes`: si bloquea salidas hacia nodos TOR conocidos.
- `firewall.enabled`: si además de loguear, ejecuta reglas `iptables` reales
  (por defecto `false` — modo dry-run, solo imprime el comando).
- `telegram.enabled`: si manda alertas por Telegram.

## Tests

```bash
pytest tests/ -v
```

## Docker

```bash
docker build -t secure-proxy -f docker/Dockerfile .
docker run -p 8888:8888 --env-file .env secure-proxy
```

## Roadmap / ideas para seguir sumando

- Cache persistente de reputación de IPs (hoy es en memoria).
- Dashboard web simple para ver bloqueos en tiempo real.
- Endpoint de métricas estilo Prometheus (`/metrics`).
- Soporte de reglas por regex además de dominios exactos.

## Aviso

Proyecto educativo/portfolio. No lo uses como única defensa contra amenazas
reales: combinalo con aislamiento real (VM/snapshots), un antivirus, y buenas
prácticas de navegación.
