"""Listas de RANGOS de IP (CIDR), con búsqueda rápida y sin dependencias.

Por qué hace falta algo distinto de `IPBlocklist`: esa compara IPs exactas,
que es lo que publica Feodo Tracker. Pero FireHOL -y casi todas las listas
serias de reputación de red- publica **rangos**, del estilo `1.10.16.0/20`.
Preguntar "¿esta IP está en alguno de estos 5.000 rangos?" recorriéndolos
uno por uno en cada conexión sería carísimo.

La solución acá es la de siempre para este problema: convertir cada rango a
un par de enteros (inicio, fin), ordenarlos una sola vez al cargar, y después
buscar con búsqueda binaria (`bisect`). Eso pasa de recorrer 5.000 rangos a
unas 12 comparaciones, y sale con la librería estándar: `ipaddress` para
entender los CIDR y `bisect` para buscar.

Los rangos que se solapan se fusionan al cargar, así la búsqueda se puede
apoyar en que la lista está ordenada y sin superposiciones.
"""

import bisect
import ipaddress
from pathlib import Path


class IPRangeBlocklist:
    """Lista de rangos de IP. Acepta CIDR (`1.2.3.0/24`) e IPs sueltas."""

    def __init__(self, path: str | list[str]):
        if isinstance(path, str):
            path = [path]
        self.paths = [Path(p) for p in path]
        self._rangos: tuple[list[int], list[int]] = ([], [])
        self.reload()

    def _parsear(self, linea: str) -> tuple[int, int] | None:
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            return None
        try:
            # strict=False acepta "1.2.3.4/24" (con bits de host puestos),
            # que aparece seguido en listas publicadas.
            red = ipaddress.ip_network(linea, strict=False)
        except ValueError:
            return None
        if red.version != 4:
            # Por ahora solo IPv4: las listas públicas de reputación son
            # casi todas v4, y mezclar las dos familias en un mismo arreglo
            # ordenado daría coincidencias falsas.
            return None
        return int(red.network_address), int(red.broadcast_address)

    def reload(self) -> None:
        crudos: list[tuple[int, int]] = []
        for path in self.paths:
            if not path.exists():
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for linea in f:
                    rango = self._parsear(linea)
                    if rango is not None:
                        crudos.append(rango)

        crudos.sort()
        inicios: list[int] = []
        fines: list[int] = []
        for inicio, fin in crudos:
            # Fusiona con el anterior si se tocan o se pisan: deja la lista
            # ordenada y sin solapamientos, que es lo que permite buscar por
            # bisección con una sola comparación.
            if fines and inicio <= fines[-1] + 1:
                fines[-1] = max(fines[-1], fin)
            else:
                inicios.append(inicio)
                fines.append(fin)
        # Se publica de UNA sola asignación, no dos. Con dos, un hilo que
        # esté atendiendo una conexión entre medio veía los inicios nuevos
        # con los fines viejos: o un IndexError que corta la conexión, o
        # -peor, porque es silencioso- un veredicto sacado del rango
        # equivocado. Las otras listas ya publicaban así.
        self._rangos = (inicios, fines)

    def is_blocked(self, ip: str) -> bool:
        inicios, fines = self._rangos  # una sola lectura, consistente
        if not inicios:
            return False
        try:
            direccion = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if direccion.version != 4:
            return False
        valor = int(direccion)
        # bisect_right da el primer rango que empieza DESPUÉS de la IP; el
        # candidato a contenerla es el anterior.
        indice = bisect.bisect_right(inicios, valor) - 1
        if indice < 0:
            return False
        return valor <= fines[indice]

    def __len__(self) -> int:
        """Cuántos rangos quedaron después de fusionar."""
        return len(self._rangos[0])

    def cantidad_de_ips(self) -> int:
        """Cuántas direcciones cubre la lista en total. Para el panel: decir
        '5.000 rangos' no da idea del alcance real, '12 millones de IPs' sí."""
        inicios, fines = self._rangos
        return sum(fin - inicio + 1 for inicio, fin in zip(inicios, fines))
