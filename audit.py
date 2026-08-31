"""
Traza de auditoria: registro encadenado, MAC por evento y verificacion.
"""
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from flask import request

from config import (
    HMAC_KEY,
    LOG_DIR,
    LOG_FILE,
    SYSLOG_ADDRESS,
    safe_mkdir,
    utc_now_iso,
)

def client_ip() -> str:
    # remote_addr ya viene corregido por ProxyFix cuando TRUSTED_PROXIES > 0.
    # Nunca se lee X-Forwarded-For a mano: era falsificable por cualquiera.
    return request.remote_addr or ""

def _canon_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def event_hash(evt: Dict[str, Any]) -> str:
    """
    Hash del evento tal y como quedó registrado. Se calcula sobre la forma
    canónica, así que no depende de cómo se serializara la línea.
    """
    clean = {k: v for k, v in evt.items() if not k.startswith("_")}
    return hashlib.sha256(_canon_json(clean)).hexdigest()

def _tail_last_event(fp) -> Optional[Dict[str, Any]]:
    """Último evento del log, leyendo solo el final del fichero."""
    fp.seek(0, os.SEEK_END)
    size = fp.tell()
    if size == 0:
        return None
    window = min(size, 8192)
    fp.seek(size - window)
    chunk = fp.read()
    # Se recorre desde el final: la primera línea del trozo puede venir
    # partida por la ventana, la última completa es la que interesa.
    for line in reversed(chunk.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None

_SYSLOG_LOGGER: Any = None

def _syslog_logger():
    """
    Envío opcional de la traza a un syslog remoto. Es la única defensa real
    frente a quien controle la máquina: la cadena de hash detecta la
    manipulación, pero no impide borrar el fichero entero.
    """
    global _SYSLOG_LOGGER
    if not SYSLOG_ADDRESS:
        return None
    if _SYSLOG_LOGGER is None:
        try:
            import logging
            import logging.handlers
            address: Any = SYSLOG_ADDRESS
            if not SYSLOG_ADDRESS.startswith("/") and ":" in SYSLOG_ADDRESS:
                host, _, port = SYSLOG_ADDRESS.rpartition(":")
                address = (host, int(port))
            handler = logging.handlers.SysLogHandler(address=address)
            logger = logging.getLogger("apk-signer-audit")
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
            logger.propagate = False
            _SYSLOG_LOGGER = logger
        except Exception:
            _SYSLOG_LOGGER = False  # no reintentar en cada evento
    return _SYSLOG_LOGGER or None

def log_event(action: str, ok: bool, **fields: Any) -> None:
    """
    Logging best-effort. NUNCA debe tumbar la app si hay permisos/FS raros.

    Cada evento encadena el hash del anterior (`prev`) y lleva un número de
    orden (`seq`). Un MAC por línea solo detecta la modificación de esa línea;
    la cadena detecta además que se hayan borrado o reordenado eventos.
    """
    try:
        safe_mkdir(LOG_DIR)
        fd = os.open(str(LOG_FILE), os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o640)
        with os.fdopen(fd, "a+", encoding="utf-8") as fp:
            # Bloqueo exclusivo: con varios workers, leer el último evento y
            # añadir el siguiente tiene que ser atómico o la cadena se parte.
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
            try:
                prev = _tail_last_event(fp)
                evt: Dict[str, Any] = {
                    "seq": int(prev.get("seq", 0)) + 1 if prev else 1,
                    "prev": event_hash(prev) if prev else "",
                    "ts": utc_now_iso(),
                    "action": action,
                    "ok": bool(ok),
                    "ip": client_ip(),
                    "ua": request.headers.get("User-Agent", ""),
                }
                for k, v in fields.items():
                    evt[k] = v
                if HMAC_KEY:
                    to_mac = dict(evt)
                    to_mac.pop("mac", None)
                    mac = hmac.new(HMAC_KEY, _canon_json(to_mac), hashlib.sha256).hexdigest()
                    evt["mac"] = mac

                line = json.dumps(evt, ensure_ascii=False)
                fp.write(line + "\n")
                fp.flush()
                os.fsync(fp.fileno())
            finally:
                fcntl.flock(fp.fileno(), fcntl.LOCK_UN)

        logger = _syslog_logger()
        if logger:
            try:
                logger.info(line)
            except Exception:
                pass
    except Exception:
        # silencio deliberado: logs no pueden romper funcionalidad.
        pass

def verify_log_chain(path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Recorre el fichero de traza entero comprobando MAC y encadenado.
    Devuelve un resumen con la primera rotura, que es lo que importa: a partir
    de ahí el resto de la cadena ya no prueba nada.
    """
    log_path = path or LOG_FILE
    summary: Dict[str, Any] = {
        "file": str(log_path),
        "events": 0,
        "unreadable": 0,
        "macOk": 0,
        "macBad": [],
        "macMissing": 0,
        "chainBad": [],
        "firstProblemSeq": None,
        "hasKey": bool(HMAC_KEY),
        "continuesFrom": None,
    }
    if not log_path.exists():
        summary["ok"] = True
        return summary

    prev_hash = ""
    expected_seq = 1
    primera_linea = True
    for raw in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            evt = json.loads(raw)
        except json.JSONDecodeError:
            summary["unreadable"] += 1
            continue

        summary["events"] += 1
        seq = evt.get("seq")

        estado, ok_mac = verify_event_mac(evt)
        if estado == "OK":
            summary["macOk"] += 1
        elif estado == "Fallo":
            summary["macBad"].append(seq)
        else:
            summary["macMissing"] += 1

        if primera_linea and evt.get("action") == "log-rotated" and evt.get("prev"):
            # Ancla de rotación: continúa legítimamente la cadena del fichero
            # anterior, así que ni su `prev` ni su `seq` empiezan de cero.
            summary["continuesFrom"] = evt.get("rotatedTo")
            expected_seq = seq if isinstance(seq, int) else expected_seq
        elif "prev" not in evt:
            # Evento anterior a la introducción de la cadena.
            summary["chainBad"].append({"seq": seq, "motivo": "sin cadena"})
        elif evt.get("prev") != prev_hash or seq != expected_seq:
            summary["chainBad"].append({
                "seq": seq,
                "motivo": "prev no coincide" if evt.get("prev") != prev_hash
                          else "numeracion discontinua",
            })

        prev_hash = event_hash(evt)
        expected_seq = (seq if isinstance(seq, int) else expected_seq) + 1
        primera_linea = False

    problemas = [s for s in summary["macBad"] if isinstance(s, int)]
    problemas += [c["seq"] for c in summary["chainBad"] if isinstance(c["seq"], int)]
    summary["firstProblemSeq"] = min(problemas) if problemas else None

    # Sin LOG_HMAC_KEY los eventos se escriben sin MAC, y entonces el
    # encadenado no prueba nada: cualquiera con acceso al fichero puede
    # reescribirlo entero y recalcular los hashes. Decir "traza íntegra" en ese
    # caso seria enganoso, asi que no se considera correcta.
    summary["ok"] = (
        bool(HMAC_KEY)
        and not summary["macBad"]
        and not summary["chainBad"]
        and not summary["unreadable"]
    )
    if not HMAC_KEY:
        summary["warning"] = (
            "No hay LOG_HMAC_KEY configurada: los eventos se registran sin MAC "
            "y la cadena no protege frente a una reescritura completa del fichero."
        )
    return summary

def verify_event_mac(evt: Dict[str, Any]) -> Tuple[str, bool]:
    """
    Devuelve (estado, ok_verificacion)
    estado: "OK", "Fallo", "Sin MAC", "Sin clave"
    """
    mac = evt.get("mac")
    if not mac:
        return ("Sin MAC", False)
    if not HMAC_KEY:
        return ("Sin clave", False)
    try:
        to_mac = dict(evt)
        to_mac.pop("mac", None)
        expected = hmac.new(HMAC_KEY, _canon_json(to_mac), hashlib.sha256).hexdigest()
        return ("OK" if hmac.compare_digest(str(mac), expected) else "Fallo", hmac.compare_digest(str(mac), expected))
    except Exception:
        return ("Fallo", False)
