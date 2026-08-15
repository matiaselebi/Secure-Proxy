"""Cliente HTTP para las llamadas que hace el PROPIO proxy hacia afuera.

Por qué existe (bug real, encontrado en producción):

`requests`, por defecto, respeta la configuración de proxy del sistema. En
Windows la lee del registro. Y resulta que el proxy del sistema es...
SecureProxy. O sea que cada vez que SecureProxy quería bajar la lista de
nodos TOR, consultar AbuseIPDB o actualizar sus feeds, se mandaba el pedido
**a sí mismo**.

Eso no es solo raro: es un bucle que se retroalimenta. El pedido entra al
proxy, el proxy lo evalúa, evaluarlo necesita la lista de TOR, bajar la
lista de TOR dispara otro pedido al proxy, y así. En la PC donde apareció,
el proxy llegó a registrar **1.644.074 conexiones al servicio que lista
los nodos de TOR en
dos días** -el 99,8% de todo el log-, con la base de datos inflada a 168 MB
y el dashboard imposible de abrir.

La regla, entonces: las conexiones que salen del proxy NUNCA pasan por el
proxy. Esta sesión lo garantiza de dos formas a la vez, porque una sola no
alcanza:

- `trust_env = False`: ignora las variables de entorno y la configuración
  de proxy del sistema.
- `proxies` explícito en `None`: por si algo más intentara inyectarla.
"""

import requests

# Una sola sesión reusada por todo el proceso: además de garantizar el
# bypass, reusa conexiones TCP en vez de abrir una nueva por descarga.
_session: requests.Session | None = None

SIN_PROXY = {"http": None, "https": None}


def session() -> requests.Session:
    """La sesión compartida que NO pasa por el proxy del sistema."""
    global _session
    if _session is None:
        nueva = requests.Session()
        nueva.trust_env = False
        nueva.proxies = dict(SIN_PROXY)
        _session = nueva
    return _session


def get(url: str, **kwargs):
    """`requests.get` que jamás sale por el proxy del sistema."""
    kwargs.setdefault("proxies", SIN_PROXY)
    return session().get(url, **kwargs)


def post(url: str, **kwargs):
    """`requests.post` que jamás sale por el proxy del sistema."""
    kwargs.setdefault("proxies", SIN_PROXY)
    return session().post(url, **kwargs)
