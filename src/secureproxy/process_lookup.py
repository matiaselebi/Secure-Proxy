"""Qué proceso de la máquina originó cada conexión.

Este es el dato que le faltaba al proyecto entero. Cuando el proxy bloquea
un pool de minería, el motivo dice "buscá qué proceso se conectó" y hasta
ahora no había forma de saberlo desde el panel: había que abrir el
Administrador de tareas y adivinar. Pero el proxy ya tiene la pieza que
hace falta. Cada conexión que le entra trae el puerto de origen del cliente,
y el sistema operativo sabe qué proceso tiene ese puerto abierto.

Así que esto va de "puerto de origen -> PID -> nombre del ejecutable", sin
dependencias nuevas:

- **Windows**: `GetExtendedTcpTable` de `iphlpapi.dll` por ctypes, que es la
  misma API que usa `netstat -ano`. El nombre sale de
  `QueryFullProcessImageNameW`.
- **Linux**: `/proc/net/tcp` da puerto -> inode del socket, y después hay
  que encontrar qué proceso tiene ese inode abierto recorriendo
  `/proc/<pid>/fd`. El nombre sale de `/proc/<pid>/comm`.

Dos cosas que importan para que esto no arruine el rendimiento:

1. **La tabla se lee entera y se cachea**, no una consulta por conexión. El
   proxy ve decenas de conexiones por segundo; pedirle al sistema la tabla
   de sockets en cada una sería carísimo. Con un cache de un segundo
   alcanza, porque el puerto de origen se resuelve apenas llega la conexión,
   cuando todavía está abierta.
2. **Si algo falla, se devuelve vacío.** Esto es información de contexto: si
   no se puede averiguar, la conexión se registra igual. Nunca puede romper
   el camino del tráfico.
"""

import os
import platform
import re
import subprocess
import threading
import time

ES_WINDOWS = platform.system() == "Windows"

# Cuánto vale un mapa de puertos antes de volver a pedirlo. Un segundo es el
# equilibrio: suficientemente fresco para que el puerto de la conexión que
# se está atendiendo todavía figure, y suficientemente largo para que una
# ráfaga de conexiones se resuelva con una sola lectura.
TTL_CACHE = 1.0

# Cuando el puerto NO está en el mapa hay que releer, porque casi siempre
# es una conexión que se abrió recién. Pero releer sin freno es peligroso:
# en Linux la lectura implica recorrer /proc entero y en una máquina con
# muchos procesos puede costar decenas de milisegundos.
#
# El freno no es un tiempo fijo, y esto costó un intento fallido: con un
# freno fijo de 250 ms, una ráfaga de conexiones (un navegador abriendo diez
# de golpe) quedaba toda sin resolver, porque la primera consumía la lectura
# y las otras nueve chocaban contra el freno. La funcionalidad andaba en las
# pruebas de a una y fallaba en el uso real.
#
# Lo que se frena en realidad no es releer: es releer AL PEDO. Así que el
# freno cuenta cuántas relecturas seguidas no encontraron lo que buscaban.
# Mientras los puertos se resuelven -el caso normal- el contador está en
# cero y no hay freno ninguno. Si empieza a fallar sistemáticamente (por
# ejemplo, sin permisos para leer la tabla), el freno crece solo hasta un
# segundo y el proxy sigue rápido aunque se pierda el nombre del proceso.
FALLOS_HASTA_FRENO_MAXIMO = 20
FRENO_MAXIMO = 1.0


class ProcessLookup:
    """Traduce un puerto de origen al proceso que lo abrió."""

    def __init__(self, habilitado: bool = True):
        self.habilitado = habilitado
        self._lock = threading.Lock()
        self._mapa: dict[int, int] = {}      # puerto -> pid
        self._leido_en = 0.0
        self._costo_lectura = 0.0            # cuánto tardó la última, en segundos
        self._fallos_seguidos = 0            # relecturas que no encontraron el puerto
        self._nombres: dict[int, str] = {}   # pid -> nombre (cache aparte)
        self.disponible = habilitado and (ES_WINDOWS or os.path.exists("/proc/net/tcp"))

    # ---------- API ----------

    def nombre_de_puerto(self, puerto: int) -> str:
        """Devuelve "ejecutable.exe (PID 1234)" o "" si no se pudo saber."""
        if not self.disponible or not puerto:
            return ""
        pid = self._pid_de_puerto(puerto)
        if pid is None:
            return ""
        nombre = self._nombre_de_pid(pid)
        return f"{nombre} (PID {pid})" if nombre else f"PID {pid}"

    # ---------- puerto -> pid ----------

    def _pid_de_puerto(self, puerto: int) -> int | None:
        with self._lock:
            edad = time.time() - self._leido_en
            freno = min(
                FRENO_MAXIMO,
                self._costo_lectura * min(self._fallos_seguidos, FALLOS_HASTA_FRENO_MAXIMO),
            )
            # Se refresca si el cache venció, y también si el puerto no está
            # (casi siempre es una conexión abierta recién).
            if edad > TTL_CACHE or (puerto not in self._mapa and edad > freno):
                inicio = time.time()
                try:
                    self._mapa = self._leer_tabla()
                except Exception:
                    # Nunca dejar que esto tumbe una conexión: es contexto.
                    self._mapa = {}
                self._leido_en = time.time()
                self._costo_lectura = self._leido_en - inicio
                if puerto in self._mapa:
                    self._fallos_seguidos = 0
                else:
                    self._fallos_seguidos += 1
            return self._mapa.get(puerto)

    def _leer_tabla(self) -> dict[int, int]:
        if ES_WINDOWS:
            return self._tabla_windows()
        return self._tabla_linux()

    # ---------- Windows ----------

    def _tabla_windows(self) -> dict[int, int]:
        import ctypes
        from ctypes import wintypes

        class MIB_TCPROW_OWNER_PID(ctypes.Structure):
            _fields_ = [
                ("dwState", wintypes.DWORD),
                ("dwLocalAddr", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("dwRemoteAddr", wintypes.DWORD),
                ("dwRemotePort", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD),
            ]

        AF_INET = 2
        TCP_TABLE_OWNER_PID_ALL = 5
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")

        # Primera llamada con buffer vacío: devuelve el tamaño que hace falta.
        tamanio = wintypes.DWORD(0)
        iphlpapi.GetExtendedTcpTable(
            None, ctypes.byref(tamanio), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
        )
        buffer = ctypes.create_string_buffer(tamanio.value)
        if iphlpapi.GetExtendedTcpTable(
            buffer, ctypes.byref(tamanio), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
        ) != 0:
            return {}

        cantidad = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]
        # Las filas arrancan justo después del contador (un DWORD).
        filas = ctypes.cast(
            ctypes.addressof(buffer) + ctypes.sizeof(wintypes.DWORD),
            ctypes.POINTER(MIB_TCPROW_OWNER_PID),
        )
        mapa: dict[int, int] = {}
        for i in range(cantidad):
            fila = filas[i]
            # El puerto viene en orden de red dentro de un DWORD: los dos
            # bytes bajos, invertidos.
            puerto = ((fila.dwLocalPort & 0xFF) << 8) + ((fila.dwLocalPort >> 8) & 0xFF)
            mapa[puerto] = fila.dwOwningPid
        return mapa

    def _nombre_windows(self, pid: int) -> str:
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.WinDLL("kernel32.dll")
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ""
        try:
            tamanio = wintypes.DWORD(1024)
            buffer = ctypes.create_unicode_buffer(tamanio.value)
            if not kernel32.QueryFullProcessImageNameW(
                handle, 0, buffer, ctypes.byref(tamanio)
            ):
                return ""
            # Solo el nombre del ejecutable: la ruta entera no entra en una
            # celda de la tabla y se ve completa en el detalle igual.
            return buffer.value.rsplit("\\", 1)[-1]
        finally:
            kernel32.CloseHandle(handle)

    # ---------- Linux ----------

    def _tabla_linux(self) -> dict[int, int]:
        """En Linux el camino es más largo: /proc/net/tcp da puerto -> inode,
        y después hay que buscar qué proceso tiene ese inode abierto."""
        puertos_por_inode: dict[str, int] = {}
        for archivo in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(archivo, "r", encoding="utf-8", errors="replace") as f:
                    next(f, None)  # encabezado
                    for linea in f:
                        campos = linea.split()
                        if len(campos) < 10:
                            continue
                        try:
                            puerto = int(campos[1].split(":")[1], 16)
                        except (IndexError, ValueError):
                            continue
                        puertos_por_inode[campos[9]] = puerto
            except OSError:
                continue

        if not puertos_por_inode:
            return {}

        mapa: dict[int, int] = {}
        for entrada in os.listdir("/proc"):
            if not entrada.isdigit():
                continue
            pid = int(entrada)
            try:
                descriptores = os.listdir(f"/proc/{pid}/fd")
            except OSError:
                continue  # proceso de otro usuario o que ya terminó
            for fd in descriptores:
                try:
                    destino = os.readlink(f"/proc/{pid}/fd/{fd}")
                except OSError:
                    continue
                if not destino.startswith("socket:["):
                    continue
                inode = destino[8:-1]
                puerto = puertos_por_inode.get(inode)
                if puerto is not None:
                    mapa[puerto] = pid
        return mapa

    def _nombre_linux(self, pid: int) -> str:
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                return f.read().strip()
        except OSError:
            return ""

    # ---------- pid -> nombre ----------

    def _nombre_de_pid(self, pid: int) -> str:
        cacheado = self._nombres.get(pid)
        if cacheado is not None:
            return cacheado
        try:
            nombre = self._nombre_windows(pid) if ES_WINDOWS else self._nombre_linux(pid)
        except Exception:
            nombre = ""
        if not nombre:
            nombre = self._nombre_por_tasklist(pid)
        # Los PID se reciclan, pero el cache se limpia solo cuando crece: para
        # el uso de un panel, un nombre viejo de vez en cuando es aceptable.
        if len(self._nombres) > 512:
            self._nombres.clear()
        self._nombres[pid] = nombre
        return nombre

    def _nombre_por_tasklist(self, pid: int) -> str:
        """Último recurso en Windows si la API no dejó abrir el proceso (pasa
        con procesos del sistema cuando el proxy no corre como administrador)."""
        if not ES_WINDOWS:
            return ""
        try:
            salida = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
        encontrado = re.match(r'"([^"]+)"', salida.strip())
        return encontrado.group(1) if encontrado else ""
