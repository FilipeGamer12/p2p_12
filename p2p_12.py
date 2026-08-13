from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import mimetypes
import os
import platform
import queue
import re
import socket
import struct
import shutil
import subprocess
import tarfile
import time
import sys
import threading
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QHBoxLayout, QPushButton
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtCore import QUrl, Qt
    from PySide6.QtGui import QMouseEvent
    PYSIDE_OK=True
except Exception:
    PYSIDE_OK=False

APP_VERSION = 2
APP_VERSION_NEW = 3  # Versão com suporte a múltiplos transportes
PREFIX = "RETROCHAT2."
PREFIX_NEW = "P2P12."  # Novo prefixo para contatos com múltiplos transportes


class BackendLog:
    def __init__(self, max_entries: int = 2000):
        self.max_entries=max_entries; self._items=[]; self._lock=threading.Lock()
    def add(self, source: str, message: object):
        item={"time":time.strftime("%Y-%m-%d %H:%M:%S"),"source":str(source).upper(),"message":str(message).replace("\x00","")}
        with self._lock:
            self._items.append(item)
            if len(self._items)>self.max_entries: del self._items[:len(self._items)-self.max_entries]
    def snapshot(self, limit=1000):
        with self._lock: return list(self._items[-max(1,min(int(limit),self.max_entries)):])

class EventQueue(queue.Queue):
    def __init__(self, log): super().__init__(); self.log=log
    def put(self,item,*args,**kwargs):
        try:
            if isinstance(item,tuple) and item:
                src='TOR' if item[0]=='tor_log' else 'APP'
                msg=item[1] if item[0]=='tor_log' and len(item)>1 else ' | '.join(str(x) for x in item)
                self.log.add(src,msg)
        except Exception: pass
        return super().put(item,*args,**kwargs)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("Base64 inválido.")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise ValueError("Base64 inválido.") from exc


def fingerprint(pub: bytes) -> str:
    digest = hashlib.sha256(pub).hexdigest().upper()
    return "-".join(digest[i : i + 4] for i in range(0, 20, 4))


def _ordered_pubs(a: bytes, b: bytes) -> tuple[bytes, bytes]:
    return (a, b) if a < b else (b, a)


@dataclass
class Identity:
    signing_key: ed25519.Ed25519PrivateKey

    @property
    def public_key(self) -> bytes:
        return self.signing_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)

    def contact_blob(self, host: str, port: int, bt_id: str = "") -> str:
        payload = {
            "v": APP_VERSION,
            "type": "retrochat-contact",
            "id": b64e(self.public_key),
            "host": str(host),
            "port": int(port),
            "bt": str(bt_id or ""),
        }
        return PREFIX + b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())

    def contact_blob_v3(self, tcp_host: str = "", tcp_port: int = 0, tor_onion: str = "", bt_id: str = "") -> str:
        """Gera um contato no novo formato (v3) com suporte a múltiplos transportes."""
        transports = {}
        
        if tcp_host:
            transports["tcp"] = {
                "host": str(tcp_host),
                "port": int(tcp_port),
                "enabled": True,
            }
        
        if tor_onion:
            transports["tor"] = {
                "onion": str(tor_onion),
                "port": int(tcp_port),  # Reutiliza a mesma porta
                "enabled": True,
            }
        
        if bt_id:
            transports["bluetooth"] = {
                "id": str(bt_id),
                "enabled": True,
            }
        
        payload = {
            "v": APP_VERSION_NEW,
            "type": "p2p12-contact",
            "id": b64e(self.public_key),
            "transports": transports,
        }
        return PREFIX_NEW + b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())

    @classmethod
    def load_or_create(cls, path: Path) -> "Identity":
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raw = b64d(path.read_text("ascii").strip())
            if len(raw) != 32:
                raise ValueError("Arquivo de identidade inválido.")
            return cls(ed25519.Ed25519PrivateKey.from_private_bytes(raw))

        key = ed25519.Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        tmp = path.with_suffix(".tmp")
        tmp.write_text(b64e(raw), encoding="ascii")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return cls(key)


def parse_contact(blob: str) -> dict:
    """Parse contatos em formato v2 (legado) ou v3 (novo com múltiplos transportes)."""
    if not isinstance(blob, str):
        raise ValueError("Contato inválido.")
    
    blob_stripped = blob.strip()
    
    # Tentar formato v3 (novo)
    if blob_stripped.startswith(PREFIX_NEW):
        return _parse_contact_v3(blob_stripped)
    
    # Tentar formato v2 (legado)
    if blob_stripped.startswith(PREFIX):
        return _parse_contact_v2(blob_stripped)
    
    raise ValueError("Contato inválido: prefixo desconhecido.")


def _parse_contact_v2(blob: str) -> dict:
    """Parse contato no formato v2 (legado RETROCHAT2)."""
    try:
        encoded = blob.split(".", 1)[1]
        payload = json.loads(b64d(encoded).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Contato corrompido.") from exc

    if payload.get("type") != "retrochat-contact" or payload.get("v") != APP_VERSION:
        raise ValueError("Versão de contato incompatível.")

    try:
        public_key = b64d(payload["id"])
        host = str(payload.get("host", "")).strip()
        port = int(payload.get("port", 0))
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("Contato inválido.") from exc

    if len(public_key) != 32:
        raise ValueError("Chave pública inválida.")
    if not 1 <= port <= 65535:
        raise ValueError("Porta inválida.")

    # Converter para formato normalizado interno
    return {
        "version": 2,
        "id_bytes": public_key,
        "transports": {
            "tcp": {
                "host": host,
                "port": port,
                "enabled": True,
            }
        },
        "host": host,  # Manter para compatibilidade
        "port": port,  # Manter para compatibilidade
    }


def _parse_contact_v3(blob: str) -> dict:
    """Parse contato no formato v3 (novo P2P12 com múltiplos transportes)."""
    try:
        encoded = blob.split(".", 1)[1]
        payload = json.loads(b64d(encoded).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Contato corrompido.") from exc

    if payload.get("type") != "p2p12-contact" or payload.get("v") != APP_VERSION_NEW:
        raise ValueError("Versão de contato incompatível.")

    try:
        public_key = b64d(payload["id"])
        transports = payload.get("transports", {})
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("Contato inválido.") from exc

    if len(public_key) != 32:
        raise ValueError("Chave pública inválida.")

    if not transports:
        raise ValueError("Contato sem transportes disponíveis.")

    # Validar cada transporte
    validated_transports = {}
    
    if "tcp" in transports:
        tcp = transports["tcp"]
        try:
            host = str(tcp.get("host", "")).strip()
            port = int(tcp.get("port", 0))
            enabled = bool(tcp.get("enabled", True))
            
            if host and (1 <= port <= 65535):
                validated_transports["tcp"] = {
                    "host": host,
                    "port": port,
                    "enabled": enabled,
                }
        except (ValueError, TypeError):
            pass
    
    if "tor" in transports:
        tor = transports["tor"]
        try:
            onion = str(tor.get("onion", "")).strip()
            port = int(tor.get("port", 0))
            enabled = bool(tor.get("enabled", True))
            
            if onion and (1 <= port <= 65535):
                validated_transports["tor"] = {
                    "onion": onion,
                    "port": port,
                    "enabled": enabled,
                }
        except (ValueError, TypeError):
            pass
    
    if "bluetooth" in transports:
        bt = transports["bluetooth"]
        try:
            bt_id = str(bt.get("id", "")).strip()
            enabled = bool(bt.get("enabled", True))
            
            if bt_id:
                validated_transports["bluetooth"] = {
                    "id": bt_id,
                    "enabled": enabled,
                }
        except (ValueError, TypeError):
            pass
    
    if not validated_transports:
        raise ValueError("Contato sem transportes válidos.")
    
    # Retornar no formato normalizado
    result = {
        "version": 3,
        "id_bytes": public_key,
        "transports": validated_transports,
    }
    
    # Adicionar campos TCP para compatibilidade (se disponível)
    if "tcp" in validated_transports:
        result["host"] = validated_transports["tcp"]["host"]
        result["port"] = validated_transports["tcp"]["port"]
    elif "tor" in validated_transports:
        result["host"] = validated_transports["tor"]["onion"]
        result["port"] = validated_transports["tor"]["port"]
    
    return result


def make_client_handshake(identity: Identity, expected_peer_pub: bytes):
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    nonce = os.urandom(16)
    first, second = _ordered_pubs(identity.public_key, expected_peer_pub)
    transcript = b"RETROCHAT-HS2-HELLO" + first + second + eph_pub + nonce
    sig = identity.signing_key.sign(transcript)
    return (
        {
            "t": "hello",
            "v": APP_VERSION,
            "id": b64e(identity.public_key),
            "ep": b64e(eph_pub),
            "n": b64e(nonce),
            "s": b64e(sig),
        },
        eph,
    )


def verify_client_handshake(msg: dict, expected_peer_pub: bytes, my_pub: bytes):
    if msg.get("t") != "hello" or msg.get("v") != APP_VERSION:
        raise ValueError("Handshake incompatível.")
    try:
        peer_pub = b64d(msg["id"])
        eph_pub = b64d(msg["ep"])
        nonce = b64d(msg["n"])
        sig = b64d(msg["s"])
    except (KeyError, ValueError) as exc:
        raise ValueError("Handshake malformado.") from exc

    if peer_pub != expected_peer_pub:
        raise ValueError("A chave pública não corresponde ao contato.")
    if len(peer_pub) != 32 or len(eph_pub) != 32 or len(nonce) != 16 or len(sig) != 64:
        raise ValueError("Handshake malformado.")

    first, second = _ordered_pubs(peer_pub, my_pub)
    transcript = b"RETROCHAT-HS2-HELLO" + first + second + eph_pub + nonce
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(peer_pub).verify(sig, transcript)
    except InvalidSignature as exc:
        raise ValueError("Falha na autenticação da identidade.") from exc
    return x25519.X25519PublicKey.from_public_bytes(eph_pub), nonce


def make_server_handshake(identity: Identity, client_pub: bytes, client_eph_pub: bytes, nonce: bytes):
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    first, second = _ordered_pubs(client_pub, identity.public_key)
    transcript = (
        b"RETROCHAT-HS2-REPLY"
        + first
        + second
        + client_eph_pub
        + eph_pub
        + nonce
    )
    sig = identity.signing_key.sign(transcript)
    return (
        {
            "t": "reply",
            "v": APP_VERSION,
            "id": b64e(identity.public_key),
            "ep": b64e(eph_pub),
            "n": b64e(nonce),
            "s": b64e(sig),
        },
        eph,
    )


def verify_server_handshake(
    msg: dict,
    expected_peer_pub: bytes,
    my_pub: bytes,
    client_eph_pub: bytes,
    nonce: bytes,
):
    if msg.get("t") != "reply" or msg.get("v") != APP_VERSION:
        raise ValueError("Resposta de handshake incompatível.")
    try:
        peer_pub = b64d(msg["id"])
        server_eph_pub = b64d(msg["ep"])
        reply_nonce = b64d(msg["n"])
        sig = b64d(msg["s"])
    except (KeyError, ValueError) as exc:
        raise ValueError("Resposta de handshake malformada.") from exc

    if peer_pub != expected_peer_pub or reply_nonce != nonce:
        raise ValueError("A identidade ou nonce do parceiro não corresponde.")
    if len(peer_pub) != 32 or len(server_eph_pub) != 32 or len(sig) != 64:
        raise ValueError("Resposta de handshake malformada.")

    first, second = _ordered_pubs(my_pub, peer_pub)
    transcript = (
        b"RETROCHAT-HS2-REPLY"
        + first
        + second
        + client_eph_pub
        + server_eph_pub
        + nonce
    )
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(peer_pub).verify(sig, transcript)
    except InvalidSignature as exc:
        raise ValueError("Falha na autenticação da resposta.") from exc
    return x25519.X25519PublicKey.from_public_bytes(server_eph_pub)


def derive_session_key(my_eph, peer_eph, my_pub: bytes, peer_pub: bytes) -> bytes:
    shared = my_eph.exchange(peer_eph)
    first, second = _ordered_pubs(my_pub, peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"RETROCHAT-SESSION2" + first + second,
    ).derive(shared)


# Backwards-compatible name for code that only needs to construct a client hello.
def make_handshake(identity: Identity, expected_peer_pub: bytes):
    return make_client_handshake(identity, expected_peer_pub)


class SecureChannel:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Chave de sessão inválida.")
        self.aead = ChaCha20Poly1305(key)

    def encrypt(self, payload: bytes, aad: bytes = b"") -> dict:
        nonce = os.urandom(12)
        return {"n": b64e(nonce), "c": b64e(self.aead.encrypt(nonce, payload, aad))}

    def decrypt(self, packet: dict, aad: bytes = b"") -> bytes:
        try:
            nonce = b64d(packet["n"])
            ciphertext = b64d(packet["c"])
        except (KeyError, ValueError) as exc:
            raise ValueError("Pacote criptográfico inválido.") from exc
        if len(nonce) != 12:
            raise ValueError("Nonce inválido.")
        return self.aead.decrypt(nonce, ciphertext, aad)


DEFAULT_PORT = 1212
MAX_FRAME = 512 * 1024
FILE_CHUNK = 48 * 1024
MAX_FILE_SIZE = 512 * 1024 * 1024


# Tor Expert Bundle oficial (ramo estável).
TOR_EXPERT_BUNDLE_VERSION = "15.0.19"
TOR_DAEMON_MIN_VERSION = "0.4.9.11"
TOR_EXPERT_BUNDLE_FILENAME = (
    f"tor-expert-bundle-windows-x86_64-{TOR_EXPERT_BUNDLE_VERSION}.tar.gz"
)
TOR_EXPERT_BUNDLE_URL = (
    f"https://archive.torproject.org/tor-package-archive/torbrowser/"
    f"{TOR_EXPERT_BUNDLE_VERSION}/{TOR_EXPERT_BUNDLE_FILENAME}"
)
TOR_DOWNLOAD_TIMEOUT = 60


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Conexão encerrada.")
        data.extend(chunk)
    return bytes(data)


def _recv(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_FRAME:
        raise ValueError("Frame inválido ou grande demais.")
    try:
        return json.loads(_recv_exact(sock, size).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Frame JSON inválido.") from exc


def _send(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ValueError("Frame grande demais.")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _safe_socket_shutdown(sock: socket.socket | None) -> None:
    if not isinstance(sock, socket.socket):
        return
    try:
        if sock.fileno() != -1:
            sock.shutdown(socket.SHUT_RDWR)
    except (OSError, ValueError):
        pass


def _safe_socket_close(sock: socket.socket | None) -> None:
    if not isinstance(sock, socket.socket):
        return
    try:
        if sock.fileno() != -1:
            sock.close()
    except (OSError, ValueError):
        pass


def _is_socket_closed_error(exc: BaseException) -> bool:
    if not isinstance(exc, OSError):
        return False
    winerr = getattr(exc, "winerror", None)
    errnum = getattr(exc, "errno", None)
    return winerr == 10038 or errnum in {9, 10038}


@dataclass
class Connection:
    sock: socket.socket
    peer_pub: bytes
    channel: SecureChannel
    send_lock: threading.Lock


class PeerService:
    def __init__(self, identity, port: int, events: queue.Queue, download_dir: Path):
        self.identity = identity
        self.port = int(port)
        self.events = events
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.server: socket.socket | None = None
        self.stop_event = threading.Event()
        self.conn: Connection | None = None
        self.lock = threading.Lock()
        self.expected_peer_pub: bytes | None = None
        self.incoming_files: dict[str, dict] = {}

    def start(self) -> None:
        if self.server is not None:
            return
        requested = self.port
        last_error = None
        candidates = [0] if requested == 0 else range(requested, requested + 21)
        for candidate in candidates:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("0.0.0.0", candidate))
                sock.listen(8)
                self.server = sock
                self.port = sock.getsockname()[1]
                break
            except OSError as exc:
                last_error = exc
                sock.close()
        if self.server is None:
            end = requested + 20 if requested else 0
            raise OSError(f"Não foi possível abrir uma porta TCP entre {requested} e {end}: {last_error}")
        threading.Thread(target=self._accept_loop, name="retrochat-accept", daemon=True).start()
        self.events.put(("status", f"Escutando TCP na porta {self.port}."))

    def stop(self) -> None:
        self.stop_event.set()
        with self.lock:
            conn = self.conn
            self.conn = None
        if conn:
            _safe_socket_shutdown(conn.sock)
            _safe_socket_close(conn.sock)
        if self.server:
            _safe_socket_close(self.server)
            self.server = None
        for item in list(self.incoming_files.values()):
            try:
                item["path"].unlink(missing_ok=True)
            except OSError:
                pass
        self.incoming_files.clear()

    def set_expected_peer(self, pub: bytes) -> None:
        self.expected_peer_pub = bytes(pub)

    # TCP agora é exclusivamente um transporte de rede local (LAN padrão ou LAN
    # avançada via RadminVPN). Não há mais NAT/CGNAT a atravessar, então uma
    # conexão direta deve responder rápido; timeout curto para não segurar o
    # ConnectionManager antes de cair para o Tor (que é o transporte de internet).
    LAN_CONNECT_TIMEOUT = 4.0

    def connect_sync(
        self,
        host: str,
        port: int,
        expected: bytes,
        cancel_event: threading.Event | None = None,
    ) -> bool:
        """Tenta uma conexão TCP direta (LAN) de forma síncrona e cancelável.

        Roda dentro da própria thread do chamador (ConnectionManager), então não
        existe mais uma thread "órfã" de conexão que continue tentando em segundo
        plano depois que o chamador desistiu.
        """
        if not host:
            raise ValueError("O contato não contém um endereço de rede (modo LAN).")
        if cancel_event is not None and cancel_event.is_set():
            raise ConnectionError("Cancelado.")

        sock: socket.socket | None = None
        try:
            self.events.put(("status", f"Conectando via TCP (LAN) a {host}:{port}..."))
            sock = socket.create_connection((host, int(port)), timeout=self.LAN_CONNECT_TIMEOUT)
            sock.settimeout(None)
            if cancel_event is not None and cancel_event.is_set():
                raise ConnectionError("Cancelado.")
            hello, eph = make_client_handshake(self.identity, expected)
            client_eph_pub = eph.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            nonce = b64d(hello["n"])
            _send(sock, hello)
            reply = _recv(sock)
            peer_eph = verify_server_handshake(
                reply, expected, self.identity.public_key, client_eph_pub, nonce
            )
            key = derive_session_key(eph, peer_eph, self.identity.public_key, expected)
            conn = Connection(sock, expected, SecureChannel(key), threading.Lock())
            self._set(conn)
            self.events.put(("online", f"TCP (LAN) em {host}:{port}"))
            threading.Thread(
                target=self._read_loop,
                args=(conn,),
                name="retrochat-read-tcp",
                daemon=True,
            ).start()
            return True
        except Exception as exc:
            _safe_socket_close(sock)
            message = "Conexão encerrada." if _is_socket_closed_error(exc) else str(exc)
            raise ConnectionError(message) from exc

    def _accept_loop(self) -> None:
        assert self.server is not None
        while not self.stop_event.is_set():
            try:
                sock, address = self.server.accept()
            except OSError:
                break
            threading.Thread(
                target=self._server,
                args=(sock, address),
                name="retrochat-peer",
                daemon=True,
            ).start()

    def _server(self, sock: socket.socket, address) -> None:
        try:
            expected = self.expected_peer_pub
            if expected is None:
                raise ValueError("Adicione um contato antes de receber conexões.")
            hello = _recv(sock)
            peer_eph, nonce = verify_client_handshake(hello, expected, self.identity.public_key)
            client_eph_pub = peer_eph.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            reply, eph = make_server_handshake(
                self.identity, expected, client_eph_pub, nonce
            )
            _send(sock, reply)
            key = derive_session_key(eph, peer_eph, self.identity.public_key, expected)
            conn = Connection(sock, expected, SecureChannel(key), threading.Lock())
            self._set(conn)
            self.events.put(("online", f"TCP de {address[0]}"))
            self._read_loop(conn)
        except Exception as exc:
            _safe_socket_close(sock)
            message = "Conexão encerrada." if _is_socket_closed_error(exc) else str(exc)
            self.events.put(("error", message))

    def _set(self, conn: Connection) -> None:
        with self.lock:
            old = self.conn
            self.conn = conn
        if old and old.sock is not conn.sock:
            _safe_socket_shutdown(old.sock)
            _safe_socket_close(old.sock)

    def _read_loop(self, conn: Connection) -> None:
        try:
            while not self.stop_event.is_set():
                packet = _recv(conn.sock)
                packet_type = packet.get("t")
                aad = b"MSG" if packet_type == "msg" else b"FILE"
                payload = conn.channel.decrypt(packet["p"], aad)
                obj = json.loads(payload.decode("utf-8"))
                kind = obj.get("t")
                if kind == "msg":
                    text = str(obj.get("text", ""))
                    self.events.put(("message", "peer", text))
                elif kind == "file_begin":
                    self._file_begin(obj)
                elif kind == "file_chunk":
                    self._file_chunk(obj)
                elif kind == "file_end":
                    self._file_end(obj)
                else:
                    raise ValueError("Tipo de pacote desconhecido.")
        except Exception as exc:
            message = "Conexão encerrada." if _is_socket_closed_error(exc) else str(exc)
            self.events.put(("offline", message))
            with self.lock:
                if self.conn is conn:
                    self.conn = None
            _safe_socket_shutdown(conn.sock)
            _safe_socket_close(conn.sock)

    def _secure_send(self, obj: dict, aad: bytes = b"MSG") -> bool:
        with self.lock:
            conn = self.conn
        if not conn:
            return False
        packet = {
            "t": "msg" if aad == b"MSG" else "file",
            "p": conn.channel.encrypt(
                json.dumps(obj, separators=(",", ":")).encode("utf-8"), aad
            ),
        }
        try:
            with conn.send_lock:
                _send(conn.sock, packet)
            return True
        except OSError as exc:
            self.events.put(("error", f"Falha no envio: {exc}"))
            return False

    def send_message(self, text: str) -> bool:
        text = str(text).strip()
        if not text or len(text.encode("utf-8")) > 16 * 1024:
            raise ValueError("Mensagem vazia ou maior que 16 KB.")
        return self._secure_send({"t": "msg", "text": text}, b"MSG")

    def send_file(self, path: Path) -> str:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(str(path))
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            raise ValueError("Arquivo maior que 512 MB.")
        fid = uuid.uuid4().hex
        digest = hashlib.sha256()
        total = (size + FILE_CHUNK - 1) // FILE_CHUNK
        safe_name = path.name.replace("\x00", "_")
        if not self._secure_send(
            {"t": "file_begin", "id": fid, "name": safe_name, "size": size, "total": total},
            b"FILE",
        ):
            raise ConnectionError("Não conectado.")
        try:
            with path.open("rb") as handle:
                for index in range(total):
                    chunk = handle.read(FILE_CHUNK)
                    digest.update(chunk)
                    if not self._secure_send(
                        {"t": "file_chunk", "id": fid, "i": index, "data": b64e(chunk)},
                        b"FILE",
                    ):
                        raise ConnectionError("Conexão perdida durante o envio.")
                    self.events.put(("file_progress", fid, index + 1, total, safe_name))
            if not self._secure_send(
                {"t": "file_end", "id": fid, "sha256": digest.hexdigest()}, b"FILE"
            ):
                raise ConnectionError("Conexão perdida ao finalizar o arquivo.")
            self.events.put(("file_sent", safe_name, size))
            return fid
        except Exception:
            raise

    def _file_begin(self, packet: dict) -> None:
        fid = str(packet.get("id", ""))
        size = int(packet.get("size", -1))
        total = int(packet.get("total", -1))
        name = Path(str(packet.get("name", "arquivo.bin"))).name
        if not fid or len(fid) > 64 or size < 0 or size > MAX_FILE_SIZE or total < 0:
            raise ValueError("Metadados de arquivo inválidos.")
        expected_total = (size + FILE_CHUNK - 1) // FILE_CHUNK
        if total != expected_total:
            raise ValueError("Quantidade de blocos inválida.")
        temp = self.download_dir / (fid + ".part")
        temp.unlink(missing_ok=True)
        self.incoming_files[fid] = {
            "path": temp,
            "name": name,
            "size": size,
            "total": total,
            "received": 0,
            "bytes": 0,
            "next_index": 0,
            "sha256": hashlib.sha256(),
        }

    def _file_chunk(self, packet: dict) -> None:
        fid = str(packet.get("id", ""))
        item = self.incoming_files.get(fid)
        if item is None:
            raise ValueError("Bloco de arquivo sem início correspondente.")
        index = int(packet.get("i", -1))
        if index != item["next_index"]:
            raise ValueError("Bloco de arquivo fora de ordem.")
        data = b64d(str(packet.get("data", "")))
        if item["bytes"] + len(data) > item["size"] or len(data) > FILE_CHUNK:
            raise ValueError("Bloco de arquivo inválido.")
        with item["path"].open("ab") as handle:
            handle.write(data)
        item["sha256"].update(data)
        item["received"] += 1
        item["bytes"] += len(data)
        item["next_index"] += 1
        self.events.put(("file_progress", fid, item["received"], item["total"], item["name"]))

    def _file_end(self, packet: dict) -> None:
        fid = str(packet.get("id", ""))
        item = self.incoming_files.pop(fid, None)
        if item is None:
            raise ValueError("Finalização de arquivo sem início correspondente.")
        try:
            if item["received"] != item["total"] or item["bytes"] != item["size"]:
                raise ValueError("Tamanho do arquivo recebido não confere.")
            expected = str(packet.get("sha256", ""))
            got = item["sha256"].hexdigest()
            if got != expected:
                raise ValueError("Hash do arquivo recebido não confere.")
            final = self.download_dir / item["name"]
            target = final
            index = 1
            while target.exists():
                target = self.download_dir / f"{final.stem} ({index}){final.suffix}"
                index += 1
            item["path"].replace(target)
            self.events.put(("file_received", target.name, str(target), item["size"]))
        except Exception:
            item["path"].unlink(missing_ok=True)
            raise


SERVICE_UUID = "9c8d0001-6e3b-4a57-9f09-726574726f01"
CHAR_UUID = "9c8d0002-6e3b-4a57-9f09-726574726f02"


# ============================================================
# TOR
# ============================================================

class TorManager:
    """Gerencia Tor como transporte P2P e Onion Service."""

    def __init__(
        self,
        events: queue.Queue,
        base_dir: Path,
        settings: dict | None = None,
        local_port: int = DEFAULT_PORT,
    ):
        self.events = events
        self.base_dir = base_dir
        self.settings = settings if isinstance(settings, dict) else {}
        self.tor_dir = base_dir / "tor"
        self.tor_dir.mkdir(parents=True, exist_ok=True)
        self.bundle_dir = self.tor_dir / "expert_bundle"
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        self.bundle_download_dir = self.tor_dir / "downloads"
        self.bundle_download_dir.mkdir(parents=True, exist_ok=True)
        self.onion_service_dir = self.tor_dir / "onion_service"
        self.onion_service_dir.mkdir(parents=True, exist_ok=True)

        self.tor_process = None
        self.control_port = 9051
        self.socks_port = 9050
        self.local_port = int(local_port)
        self.enabled = False
        self.onion_address = None
        self.state = "OFFLINE"
        self.tor_data_dir = self.tor_dir / "data"
        self.tor_data_dir.mkdir(parents=True, exist_ok=True)
        self.tor_executable = None
        self.tor_version = None
        self._start_lock = threading.Lock()

    def _tor_settings(self) -> dict:
        value = self.settings.get("tor")
        if not isinstance(value, dict):
            value = {}
            self.settings["tor"] = value
        return value

    def _save_tor_setting(self, key: str, value) -> None:
        self._tor_settings()[key] = value
        try:
            save_settings(self.base_dir, self.settings)
        except Exception as exc:
            self.events.put(("status", f"Não foi possível salvar configuração do Tor: {exc}"))

    @staticmethod
    def _version_tuple(version: str) -> tuple[int, ...]:
        return tuple(int(item) for item in re.findall(r"\d+", str(version))[:4])

    def _get_tor_version(self, tor_exe: str) -> str | None:
        try:
            result = subprocess.run(
                [tor_exe, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return None

        output = f"{result.stdout}\n{result.stderr}"
        match = re.search(
            r"\bTor version\s+([0-9]+(?:\.[0-9]+)+)",
            output,
            re.IGNORECASE,
        )
        if not match:
            match = re.search(
                r"\bversion\s+([0-9]+(?:\.[0-9]+)+)",
                output,
                re.IGNORECASE,
            )
        return match.group(1) if match else None

    def _is_tor_compatible(self, tor_exe: str) -> bool:
        version = self._get_tor_version(tor_exe)
        self.tor_version = version
        if not version:
            return False
        return self._version_tuple(version) >= self._version_tuple(TOR_DAEMON_MIN_VERSION)

    def start(self) -> bool:
        """Garante um Tor utilizável e o inicia em segundo plano quando necessário."""
        with self._start_lock:
            return self._start_locked()

    def _start_locked(self) -> bool:
        if self.enabled and self._tor_already_running():
            return True

        if self._tor_already_running():
            self.enabled = True
            self.state = "ONLINE"
            self._load_onion_address()
            self.events.put(("tor_state", "ONLINE"))
            return True

        try:
            self.state = "STARTING"
            self.events.put(("tor_state", "STARTING"))

            tor_exe = self._ensure_tor_executable()
            self.tor_executable = tor_exe
            self._save_tor_setting("executable", tor_exe)
            if self.tor_version:
                self._save_tor_setting("version", self.tor_version)

            self._create_torrc(tor_exe)
            self._start_tor_process(tor_exe)

            if not self._wait_tor_bootstrap():
                raise ConnectionError("Tor não inicializou no tempo esperado.")

            self._load_onion_address()
            if not self.onion_address:
                self._generate_onion_address()

            self.enabled = True
            self.state = "ONLINE"
            self.events.put(("tor_state", "ONLINE"))
            return True

        except Exception as exc:
            self.state = "ERROR"
            self.events.put(("tor_state", f"ERROR: {exc}"))
            self.stop()
            return False

    def stop(self) -> None:
        """Para somente o processo Tor iniciado por este aplicativo."""
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=5)
            except Exception:
                try:
                    self.tor_process.kill()
                except Exception:
                    pass
            self.tor_process = None

        self.state = "OFFLINE"
        self.events.put(("tor_state", "OFFLINE"))
        self.enabled = False

    def _find_tor_executable(self) -> str | None:
        """Localiza o caminho configurado e, depois, uma instalação do sistema."""
        configured = str(self._tor_settings().get("executable", "") or "").strip()
        candidates = [Path(configured)] if configured else []

        if platform.system() == "Windows":
            command = "where"
            common_paths = [
                Path(r"C:\Program Files\Tor\tor.exe"),
                Path(r"C:\Program Files (x86)\Tor\tor.exe"),
            ]
            try:
                local_appdata = Path(os.environ.get("LOCALAPPDATA", ""))
                if str(local_appdata):
                    common_paths.extend(local_appdata.glob("Tor Browser/**/tor.exe"))
            except Exception:
                pass
        else:
            command = "which"
            common_paths = [
                Path("/usr/bin/tor"),
                Path("/usr/local/bin/tor"),
                Path("/opt/tor/bin/tor"),
                Path("/opt/homebrew/bin/tor"),
            ]

        candidates.extend(common_paths)
        try:
            result = subprocess.run(
                [command, "tor"],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0 and result.stdout.strip():
                candidates.append(Path(result.stdout.strip().splitlines()[0]))
        except Exception:
            pass

        seen = set()
        for candidate in candidates:
            try:
                resolved = str(candidate.expanduser().resolve())
            except Exception:
                resolved = str(candidate.expanduser())
            if resolved in seen:
                continue
            seen.add(resolved)
            if os.path.isfile(resolved):
                return resolved
        return None

    def _ensure_tor_executable(self) -> str:
        """Retorna Tor compatível; no Windows baixa o Expert Bundle se necessário."""
        found = self._find_tor_executable()

        if found and self._is_tor_compatible(found):
            self.events.put(("status", f"Tor encontrado: {self.tor_version}"))
            return found

        if found:
            old_version = self.tor_version or "desconhecida"
            self.events.put(
                (
                    "status",
                    f"Tor encontrado, mas desatualizado ({old_version}). "
                    "Baixando Tor Expert Bundle...",
                )
            )
        else:
            self.events.put(("status", "Tor não encontrado. Baixando Tor Expert Bundle..."))

        if not bool(self._tor_settings().get("auto_download", True)):
            raise FileNotFoundError(
                "Tor compatível não encontrado e o download automático do Expert Bundle está desativado."
            )

        if platform.system() != "Windows":
            raise FileNotFoundError(
                "Tor compatível não encontrado automaticamente neste sistema. "
                "O download automático do Expert Bundle está implementado para Windows x86_64."
            )

        if platform.machine().lower() not in {"amd64", "x86_64", "x64"}:
            raise OSError("O Tor Expert Bundle configurado é para Windows x86_64.")

        return self._download_and_install_expert_bundle()

    def _download_and_install_expert_bundle(self) -> str:
        """Baixa e extrai o Expert Bundle estável oficial."""
        archive_path = self.bundle_download_dir / TOR_EXPERT_BUNDLE_FILENAME
        extract_root = self.bundle_dir / TOR_EXPERT_BUNDLE_VERSION

        if extract_root.exists():
            tor_exe = next(extract_root.rglob("tor.exe"), None)
            if tor_exe and self._is_tor_compatible(str(tor_exe)):
                self.events.put(
                    ("status", f"Tor Expert Bundle {TOR_EXPERT_BUNDLE_VERSION} já está instalado.")
                )
                self._save_tor_setting("bundle_version", TOR_EXPERT_BUNDLE_VERSION)
                self._save_tor_setting("executable", str(tor_exe))
                return str(tor_exe)

        self.events.put(("status", f"Baixando Tor Expert Bundle {TOR_EXPERT_BUNDLE_VERSION}..."))
        temporary_archive = archive_path.with_suffix(archive_path.suffix + ".part")
        request = urllib.request.Request(
            TOR_EXPERT_BUNDLE_URL,
            headers={"User-Agent": "P2P12-TorManager/1.0"},
        )
        with urllib.request.urlopen(request, timeout=TOR_DOWNLOAD_TIMEOUT) as response:
            with temporary_archive.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
        os.replace(temporary_archive, archive_path)

        self.events.put(("status", "Extraindo Tor Expert Bundle..."))
        temp_extract = self.bundle_dir / f".extract-{TOR_EXPERT_BUNDLE_VERSION}"
        if temp_extract.exists():
            shutil.rmtree(temp_extract, ignore_errors=True)
        temp_extract.mkdir(parents=True, exist_ok=True)

        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                base = temp_extract.resolve()
                for member in archive.getmembers():
                    target = (temp_extract / member.name).resolve()
                    if target != base and base not in target.parents:
                        raise ValueError("Arquivo do Tor Expert Bundle contém caminho inválido.")
                archive.extractall(temp_extract)

            if extract_root.exists():
                shutil.rmtree(extract_root, ignore_errors=True)
            shutil.move(str(temp_extract), str(extract_root))
        finally:
            if temp_extract.exists():
                shutil.rmtree(temp_extract, ignore_errors=True)

        tor_exe = next(extract_root.rglob("tor.exe"), None)
        if not tor_exe:
            raise FileNotFoundError(
                "O Tor Expert Bundle foi extraído, mas tor.exe não foi encontrado."
            )

        tor_exe = str(tor_exe)
        if not self._is_tor_compatible(tor_exe):
            raise RuntimeError(
                f"O tor.exe baixado não atende à versão mínima {TOR_DAEMON_MIN_VERSION}."
            )

        self._save_tor_setting("executable", tor_exe)
        self._save_tor_setting("bundle_version", TOR_EXPERT_BUNDLE_VERSION)
        self._save_tor_setting("version", self.tor_version)
        return tor_exe

    def _create_torrc(self, tor_exe: str) -> None:
        """Configura o Onion Service na porta real do PeerService."""
        torrc_path = self.tor_dir / "torrc"
        torrc_content = f"""# P2P-12 Tor Configuration
SocksPort 127.0.0.1:{self.socks_port}
ControlPort 127.0.0.1:{self.control_port}
DataDirectory {self.tor_data_dir}
HiddenServiceDir {self.onion_service_dir}
HiddenServicePort {self.local_port} 127.0.0.1:{self.local_port}
Log notice stdout
"""
        torrc_path.write_text(torrc_content, encoding="utf-8")

    def _start_tor_process(self, tor_exe: str) -> None:
        """Inicia Tor em segundo plano, sem abrir janela no Windows."""
        torrc_path = self.tor_dir / "torrc"
        self.tor_process = subprocess.Popen(
            [tor_exe, "-f", str(torrc_path)],
            cwd=str(Path(tor_exe).parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for stream_name, stream in (("stdout", self.tor_process.stdout), ("stderr", self.tor_process.stderr)):
            if stream is not None:
                threading.Thread(target=self._read_tor_log_stream, args=(stream_name, stream), daemon=True, name=f"tor-log-{stream_name}").start()

    def _read_tor_log_stream(self, stream_name: str, stream) -> None:
        try:
            for line in iter(stream.readline, ''):
                line=line.rstrip()
                if line:
                    self.events.put(('tor_log', f'{stream_name}: {line}'))
        except Exception as exc:
            self.events.put(('tor_log', f'{stream_name}: {exc}'))

    def _wait_tor_bootstrap(self, timeout: float = 60) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.tor_process and self.tor_process.poll() is not None:
                return False
            if self._tor_already_running():
                time.sleep(1)
                return True
            time.sleep(0.5)
        return False

    def _tor_already_running(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.control_port), timeout=1):
                return True
        except OSError:
            return False

    def _generate_onion_address(self) -> None:
        for _ in range(100):
            hostname_file = self.onion_service_dir / "hostname"
            if hostname_file.exists():
                self.onion_address = hostname_file.read_text(encoding="utf-8").strip()
                return
            time.sleep(0.1)
        raise FileNotFoundError("Tor não criou hostname Onion.")

    def _load_onion_address(self) -> None:
        hostname_file = self.onion_service_dir / "hostname"
        if hostname_file.exists():
            self.onion_address = hostname_file.read_text(encoding="utf-8").strip()

    def get_onion_address(self) -> str | None:
        return self.onion_address

    def is_online(self) -> bool:
        return self.state == "ONLINE" and self.enabled

def connect_via_socks5(host: str, port: int, socks_host: str = "127.0.0.1", socks_port: int = 9050, timeout: float = 10) -> socket.socket:
    """Conecta a um host via SOCKS5."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        # Conectar ao proxy SOCKS5
        sock.connect((socks_host, socks_port))
        
        # Enviar saudação SOCKS5: versão 5, sem autenticação
        sock.sendall(b'\x05\x01\x00')
        
        # Receber resposta de saudação
        response = sock.recv(2)
        if len(response) < 2 or response[0] != 0x05:
            raise ConnectionError("Resposta SOCKS5 inválida")
        
        # Enviar comando de conexão
        # Formato: [VER=5][CMD=1][RSV=0][ATYP][DST.ADDR][DST.PORT]
        host_bytes = host.encode('ascii')
        
        if host.endswith('.onion'):
            # Tipo de endereço: nome de domínio
            atyp = b'\x03'
            addr_field = bytes([len(host_bytes)]) + host_bytes
        else:
            # Tentar como endereço IP
            try:
                ip_bytes = socket.inet_aton(host)
                atyp = b'\x01'
                addr_field = ip_bytes
            except socket.error:
                # Se não for IP, tratar como nome de domínio
                atyp = b'\x03'
                addr_field = bytes([len(host_bytes)]) + host_bytes
        
        # Porta em big-endian
        port_bytes = struct.pack('!H', port)
        
        # Montar comando de conexão
        command = b'\x05\x01\x00' + atyp + addr_field + port_bytes
        sock.sendall(command)
        
        # Receber resposta de conexão
        response = sock.recv(1024)
        if len(response) < 2 or response[0] != 0x05:
            raise ConnectionError("Resposta de conexão SOCKS5 inválida")
        
        if response[1] != 0x00:
            error_messages = {
                0x01: "Erro geral SOCKS",
                0x02: "Conexão não permitida",
                0x03: "Rede indisponível",
                0x04: "Host indisponível",
                0x05: "Conexão recusada",
                0x06: "TTL expirado",
                0x07: "Comando não suportado",
                0x08: "Tipo de endereço não suportado",
            }
            error_msg = error_messages.get(response[1], f"Erro SOCKS5: {response[1]}")
            raise ConnectionError(error_msg)
        
        return sock
    
    except Exception:
        sock.close()
        raise


def _recv_exact_socks(sock: socket.socket, size: int) -> bytes:
    """Recebe exatamente 'size' bytes, tratando como dados SOCKS5."""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Conexão SOCKS5 encerrada.")
        data.extend(chunk)
    return bytes(data)


# ============================================================
# CONNECTION MANAGER
# ============================================================

class ConnectionManager:
    """Gerencia tentativas de conexão através de múltiplos transportes."""
    
    def __init__(self, identity: "Identity", events: queue.Queue, service: "PeerService", tor_manager: TorManager, settings: dict):
        self.identity = identity
        self.events = events
        self.service = service
        self.tor_manager = tor_manager
        self.settings = settings
        
        self.peer_data = None
        self.cancel_event = threading.Event()
        self.attempt_thread = None
        self.current_transport = None
        self.state = "OFFLINE"
    
    def connect(self, peer_data: dict) -> None:
        """Inicia tentativa de conexão para o peer fornecido."""
        self.peer_data = peer_data
        self.cancel_event.clear()
        self.current_transport = None
        self.state = "CONNECTING"
        
        self.attempt_thread = threading.Thread(
            target=self._attempt_connection,
            name="retrochat-connect-manager",
            daemon=True
        )
        self.attempt_thread.start()
    
    def cancel(self) -> None:
        """Cancela a tentativa de conexão em andamento."""
        self.cancel_event.set()
        self.state = "CANCELLED"
        self.events.put(("status", "Conexão cancelada."))
    
    def _attempt_connection(self) -> None:
        """Tenta conectar através dos transportes habilitados."""
        try:
            transports = self.peer_data.get("transports", {})
            
            # Lista de transportes a tentar (TCP primeiro, depois Tor)
            attempts = []
            
            if self.settings['transports']['tcp'] and 'tcp' in transports:
                attempts.append(('tcp', transports['tcp']))
            
            if self.settings['transports']['tor'] and 'tor' in transports:
                attempts.append(('tor', transports['tor']))
            
            if not attempts:
                self.events.put(("status", "Nenhum transporte disponível."))
                self.state = "ERROR"
                return
            
            # Tentar transportes em ordem
            for transport_name, transport_config in attempts:
                if self.cancel_event.is_set():
                    self.state = "CANCELLED"
                    return
                
                try:
                    if transport_name == 'tcp':
                        self._try_tcp(transport_config)
                    elif transport_name == 'tor':
                        self._try_tor(transport_config)
                    
                    # Se chegou aqui, a conexão foi bem-sucedida
                    self.current_transport = transport_name
                    self.state = "ONLINE"
                    self.events.put(("status", f"ONLINE — {transport_name.upper()}"))
                    return
                except Exception as e:
                    self.events.put(("status", f"Falha em {transport_name}: {e}"))
                    continue
            
            # Se nenhum transporte funcionou
            self.state = "ERROR"
            self.events.put(("status", "Falha ao conectar em todos os transportes."))
        
        except Exception as e:
            self.state = "ERROR"
            self.events.put(("status", f"Erro na conexão: {e}"))
    
    def _try_tcp(self, config: dict) -> None:
        """Tenta conectar via TCP (modo LAN — rede local ou LAN avançada via RadminVPN)."""
        host = config.get('host', '')
        port = config.get('port', DEFAULT_PORT)
        
        if not host:
            raise ValueError("Host TCP não configurado.")
        
        # Síncrono e cancelável: roda na própria thread deste ConnectionManager,
        # então quando desistimos aqui não fica nenhuma tentativa "órfã" tentando
        # se conectar em segundo plano e sobrescrevendo uma conexão Tor posterior.
        self.service.connect_sync(host, port, self.peer_data['id_bytes'], self.cancel_event)
    
    def _try_tor(self, config: dict) -> None:
        """Tenta conectar via Tor com retentativas."""
        onion = config.get('onion', '')
        port = config.get('port', DEFAULT_PORT)
        
        if not onion:
            raise ValueError("Endereço Onion não configurado.")

        # Iniciar/reutilizar o Tor somente quando o transporte Tor for usado.
        if not self.tor_manager.start():
            raise ConnectionError("Não foi possível iniciar o Tor.")
        
        # Tentar Tor até sucesso ou cancelamento
        attempt_count = 0
        while not self.cancel_event.is_set():
            attempt_count += 1
            self.events.put(("status", f"Conectando via Tor (tentativa #{attempt_count})..."))
            
            try:
                self._tor_attempt(onion, port)
                return  # Sucesso
            except Exception as e:
                if attempt_count > 100:  # Limite de 100 tentativas
                    raise ConnectionError(f"Limite de tentativas Tor excedido: {e}")
                
                # Pequeno delay antes de tentar novamente
                for _ in range(20):  # ~2 segundos
                    if self.cancel_event.is_set():
                        raise ConnectionError("Cancelado.")
                    threading.Event().wait(0.1)
    
    def _tor_attempt(self, onion: str, port: int) -> None:
        """Uma única tentativa de conexão via Tor."""
        sock = None
        try:
            # Conectar via SOCKS5
            sock = connect_via_socks5(onion, port, timeout=10)
            sock.settimeout(None)
            
            # Fazer handshake
            hello, eph = make_client_handshake(self.identity, self.peer_data['id_bytes'])
            client_eph_pub = eph.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            nonce = b64d(hello["n"])
            
            _send(sock, hello)
            reply = _recv(sock)
            
            peer_eph = verify_server_handshake(
                reply, self.peer_data['id_bytes'], self.identity.public_key, client_eph_pub, nonce
            )
            
            key = derive_session_key(eph, peer_eph, self.identity.public_key, self.peer_data['id_bytes'])
            
            # Conexão bem-sucedida - configurar no serviço
            channel = SecureChannel(key)
            conn = Connection(
                sock=sock,
                peer_pub=self.peer_data['id_bytes'],
                channel=channel,
                send_lock=threading.Lock()
            )
            
            self.service._set(conn)
            self.service.events.put(("online", "Tor"))
            
            # Iniciar read loop em thread separada
            threading.Thread(
                target=self.service._read_loop,
                args=(conn,),
                name="retrochat-read",
                daemon=True
            ).start()
        
        except Exception:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            raise


class BluetoothManager:
    """BLE discovery layer.

    The scanner is intentionally isolated from the TCP transport. A future
    GATT transport can use the same encrypted protocol without changing the UI.
    """

    def __init__(self, events):
        self.events = events
        self.loop = None
        self.thread = None
        self.enabled = False
        self.scanning = False

    def start(self):
        try:
            import bleak  # noqa: F401
            self.enabled = True
            self.events.put(("bt_status", "Bluetooth BLE disponível."))
        except Exception as exc:
            self.events.put(("bt_status", f"Bluetooth BLE indisponível: {exc}"))

    def scan(self):
        if not self.enabled or self.scanning:
            return False
        self.scanning = True
        threading.Thread(target=self._scan, name="retrochat-bt-scan", daemon=True).start()
        return True

    def _scan(self):
        async def run():
            from bleak import BleakScanner
            devices = await BleakScanner.discover(timeout=5)
            result = []
            for device in devices:
                result.append({
                    "name": device.name or "Bluetooth",
                    "address": device.address,
                })
            return result

        try:
            devices = asyncio.run(run())
            self.events.put(("bt_devices", devices))
        except Exception as exc:
            self.events.put(("error", f"Bluetooth: {exc}"))
        finally:
            self.scanning = False

    def stop(self):
        self.scanning = False


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "RetroChatHTTP/1.0"

    def log_message(self, *args):
        pass

    @property
    def app(self):
        return self.server.app  # type: ignore[attr-defined]

    def _send(self, code: int, body, ctype: str = "application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self) -> dict:
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size > 256 * 1024:
                raise ValueError("Requisição JSON grande demais.")
            return json.loads(self.rfile.read(size).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("JSON inválido.") from exc

    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                return self._send(200, self.app.html, "text/html; charset=utf-8")
            if parsed.path == "/api/info":
                return self._send(200, json.dumps(self.app.info(), ensure_ascii=False))
            if parsed.path == "/api/poll":
                return self._send(200, json.dumps(self.app.poll(), ensure_ascii=False))
            if parsed.path == "/api/settings":
                return self._send(200, json.dumps(self.app.get_settings(), ensure_ascii=False))
            if parsed.path == "/api/tor/status":
                return self._send(200, json.dumps({
                    "enabled": self.app.tor.enabled,
                    "state": self.app.tor.state,
                    "onion_address": self.app.tor.get_onion_address(),
                    "executable": self.app.tor.tor_executable,
                    "version": self.app.tor.tor_version,
                }, ensure_ascii=False))
            if parsed.path == "/api/debug/logs":
                return self._send(200, json.dumps({"logs": self.app.get_debug_logs()}, ensure_ascii=False))
            if parsed.path == "/api/radminvpn/status":
                return self._send(200, json.dumps({"mode": self.app.settings.get('tcp', {}).get('mode', 'standard'), "ip": self.app.get_radminvpn_ip()}, ensure_ascii=False))
            if parsed.path.startswith("/download/"):
                name = Path(urllib.parse.unquote(parsed.path[len("/download/"):])).name
                root = self.app.download_dir.resolve()
                file_path = (root / name).resolve()
                if root not in file_path.parents or not file_path.is_file():
                    return self._send(404, b"Not found", "text/plain; charset=utf-8")
                self._send_file(file_path, name)
                return
            return self._send(404, b"Not found", "text/plain; charset=utf-8")
        except Exception as exc:
            return self._send(500, json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))

    def _send_file(self, path: Path, name: str):
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", f'attachment; filename="{name.replace(chr(34), "_")}"')
        self.end_headers()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def do_POST(self):
        try:
            if self.path == "/api/contact":
                payload = self._json()
                contact = payload.get("contact", "")
                peer = parse_contact(contact)
                self.app.set_peer(peer)
                return self._send(
                    200,
                    json.dumps(
                        {
                            "ok": True,
                            "fingerprint": self.app.peer_fingerprint,
                            "host": peer.get("host", ""),
                            "port": peer.get("port", DEFAULT_PORT),
                        },
                        ensure_ascii=False,
                    ),
                )

            if self.path == "/api/connect":
                self.app.connect()
                return self._send(200, '{"ok":true}')

            if self.path == "/api/cancel":
                self.app.cancel_connect()
                return self._send(200, '{"ok":true}')

            if self.path == "/api/message":
                text = self._json().get("text", "")
                if not self.app.service.send_message(text):
                    raise ConnectionError("Não há conexão ativa.")
                return self._send(200, '{"ok":true}')

            if self.path == "/api/file":
                return self._receive_upload()

            if self.path == "/api/bluetooth/scan":
                if not self.app.bluetooth.scan():
                    raise RuntimeError("Bluetooth indisponível ou uma busca já está em andamento.")
                return self._send(200, '{"ok":true}')

            if self.path == "/api/settings":
                new_settings = self._json()
                self.app.set_settings(new_settings)
                return self._send(200, json.dumps(self.app.get_settings(), ensure_ascii=False))

            return self._send(404, b"Not found", "text/plain; charset=utf-8")
        except Exception as exc:
            return self._send(400, json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))

    def _receive_upload(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            raise ValueError("Upload vazio.")
        if content_length > MAX_FILE_SIZE + 1024 * 1024:
            raise ValueError("Upload maior que 512 MB.")

        content_type = self.headers.get("Content-Type", "")
        match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", content_type)
        if not content_type.startswith("multipart/form-data") or not match:
            raise ValueError("Upload inválido.")
        boundary = (match.group(1) or match.group(2)).encode()

        body = self.rfile.read(content_length)
        marker = b"\r\n\r\n"
        parts = body.split(b"--" + boundary)
        found = None
        filename = "arquivo.bin"

        for part in parts:
            if b"filename=" not in part or marker not in part:
                continue
            head, data = part.split(marker, 1)
            data = data.rstrip(b"\r\n-")
            text = head.decode("utf-8", "ignore")
            file_match = re.search(r'filename="([^"]*)"', text)
            filename = file_match.group(1) if file_match else filename
            found = data
            break

        if found is None:
            raise ValueError("Nenhum arquivo enviado.")
        if len(found) > MAX_FILE_SIZE:
            raise ValueError("Arquivo maior que 512 MB.")
        if not self.app.service.conn:
            raise ConnectionError("Não há conexão ativa.")

        safe_name = Path(filename).name or "arquivo.bin"
        temp = self.app.temp_dir / (os.urandom(8).hex() + "-" + safe_name)
        temp.write_bytes(found)

        def send_and_cleanup():
            try:
                self.app.service.send_file(temp)
            except Exception as exc:
                self.app.events.put(("error", f"Envio de arquivo: {exc}"))
            finally:
                try:
                    temp.unlink(missing_ok=True)
                except OSError:
                    pass

        threading.Thread(target=send_and_cleanup, name="retrochat-file-send", daemon=True).start()
        return self._send(
            200,
            json.dumps({"ok": True, "name": safe_name, "size": len(found)}, ensure_ascii=False),
        )


class ApiServer:
    def __init__(self, app):
        self.app = app
        self.httpd = None

    def start(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
        self.httpd.app = self.app
        threading.Thread(target=self.httpd.serve_forever, name="retrochat-http", daemon=True).start()
        return self.httpd.server_address[1]

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


if PYSIDE_OK:
    class RetroWindow(QWidget):
        def __init__(self, url):
            super().__init__()
            self.setWindowTitle('p2p_12')
            self.setWindowFlags(Qt.WindowType.Window)
            self.resize(1100, 760)
            self.setMinimumSize(800, 500)
            self.setStyleSheet('background: #c0c0c0;')

            root = QVBoxLayout(self)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)

            self.view = QWebEngineView(self)
            root.addWidget(self.view, 1)
            self.view.setUrl(QUrl(url))

            # Usa o frame nativo do sistema operacional, preservando o layout visual
            # já definido na interface web em vez de um title bar customizado.



ROOT=Path(__file__).resolve().parent
HTML=(ROOT/'web'/'index.html').read_text(encoding='utf-8')

def data_dir(profile=None):
    base=Path.home()/'.p2p_12'
    if profile:
        safe=''.join(c for c in profile if c.isalnum() or c in '-_').strip()
        if not safe: raise ValueError('Perfil inválido.')
        base=base/safe
    return base

def local_ip():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:s.connect(('1.1.1.1',80)); return s.getsockname()[0]
    except OSError:return '127.0.0.1'
    finally:s.close()


def load_settings(base_dir: Path) -> dict:
    """Carrega as configurações do usuário ou retorna padrões."""
    settings_file = base_dir / 'settings.json'
    defaults = {
        'transports': {
            'tcp': True,
            'tor': True,
            'bluetooth': False,
        },
        'tcp': {'mode': 'standard'},
        'tor': {
            'executable': '',
            'version': '',
            'bundle_version': '',
            'auto_download': True,
        },
        'theme': 'dark',
    }
    if not settings_file.exists():
        return defaults
    try:
        with settings_file.open('r', encoding='utf-8') as f:
            data = json.load(f)
        # Garantir que todas as chaves necessárias existem
        if 'transports' not in data:
            data['transports'] = defaults['transports']
        if 'theme' not in data:
            data['theme'] = defaults['theme']
        if 'tcp' not in data or not isinstance(data['tcp'], dict):
            data['tcp'] = {}
        if data['tcp'].get('mode') not in {'standard', 'radminvpn'}:
            data['tcp']['mode'] = 'standard'
        if 'tor' not in data or not isinstance(data['tor'], dict):
            data['tor'] = {}
        for key, value in defaults['tor'].items():
            if key not in data['tor']:
                data['tor'][key] = value
        # Garantir que todos os transportes estão presentes
        for transport in defaults['transports']:
            if transport not in data['transports']:
                data['transports'][transport] = defaults['transports'][transport]
        return data
    except (json.JSONDecodeError, OSError):
        return defaults


def save_settings(base_dir: Path, settings: dict) -> None:
    """Salva as configurações do usuário."""
    settings_file = base_dir / 'settings.json'
    try:
        with settings_file.open('w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
    except OSError as e:
        print(f'Erro ao salvar configurações: {e}', file=sys.stderr)


class App:
    def __init__(self, profile=None):
        self.base=data_dir(profile); self.base.mkdir(parents=True,exist_ok=True); self.download_dir=self.base/'Downloads'; self.download_dir.mkdir(exist_ok=True); self.temp_dir=self.base/'tmp'; self.temp_dir.mkdir(exist_ok=True)
        self.settings = load_settings(self.base)
        self.identity = Identity.load_or_create(self.base / 'identity.key')
        self.log_buffer = BackendLog()
        self.log_buffer.add('APP', 'Backend iniciado.')
        self.events = EventQueue(self.log_buffer)
        requested_port = int(os.environ.get('RETROCHAT_PORT', DEFAULT_PORT))
        self.service = PeerService(self.identity, requested_port, self.events, self.download_dir)
        self.service.start()
        self.port = self.service.port
        self.peer = None
        self.peer_fingerprint = ''
        self.tor = TorManager(
            self.events,
            self.base,
            self.settings,
            local_port=self.port,
        )
        self.bluetooth = BluetoothManager(self.events)
        if self.settings['transports']['bluetooth']:
            self.bluetooth.start()
        if self.settings['transports']['tor']:
            threading.Thread(target=self.tor.start, name="retrochat-tor-boot", daemon=True).start()
        self.connection_manager = ConnectionManager(self.identity, self.events, self.service, self.tor, self.settings)
        self.http = ApiServer(self)
        self.web_port = self.http.start()
        self.html = HTML
    def get_debug_logs(self, limit: int = 1000):
        return self.log_buffer.snapshot(limit)

    def get_radminvpn_ip(self) -> str | None:
        if platform.system() != 'Windows':
            return None
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, encoding='mbcs', errors='replace', timeout=5, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            return None
        in_radmin = False
        fallback = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped and not line[:1].isspace():
                in_radmin = 'radmin vpn' in stripped.lower()
                continue
            m = re.search(r'(?:IPv4[^:]*|Endere[cç]o IPv4[^:]*):\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})', stripped, re.I)
            if m:
                ip=m.group(1)
                if in_radmin and ip.startswith('26.'):
                    return ip
                if ip.startswith('26.') and fallback is None:
                    fallback=ip
        return fallback

    def get_tcp_host(self, lan_host: str) -> str:
        """TCP é sempre um transporte de rede local: 'standard' anuncia o IP da
        LAN normal; 'radminvpn' anuncia o IP da rede virtual RadminVPN (LAN
        avançada), que só existe para permitir esse mesmo tipo de conexão direta
        entre redes físicas diferentes."""
        if self.settings.get('tcp', {}).get('mode', 'standard') == 'radminvpn':
            ip = self.get_radminvpn_ip()
            if ip:
                return ip
            self.log_buffer.add('APP', 'Modo RadminVPN ativo, mas o adaptador Radmin VPN não foi detectado; usando o IP de LAN padrão.')
        return lan_host

    def info(self):
        lan_host = local_ip()
        tcp_host = self.get_tcp_host(lan_host)
        tor_onion = self.tor.get_onion_address() if self.tor.is_online() else ''
        # Sempre no formato v3: TCP (LAN) e Tor (internet) juntos, para que o
        # modo RadminVPN e o estado atual do Tor sejam sempre respeitados no
        # contato copiado — nunca mais um formato "silenciosamente" incompleto.
        contact = self.identity.contact_blob_v3(
            tcp_host=tcp_host,
            tcp_port=self.port,
            tor_onion=tor_onion,
        )
        return {
            'fingerprint': self.identity.fingerprint,
            'contact': contact,
            'tor_onion': tor_onion,
            'tor_state': self.tor.state,
            'host': lan_host,
            'tcp_host': tcp_host,
            'tcp_mode': self.settings.get('tcp', {}).get('mode', 'standard'),
            'radminvpn_ip': self.get_radminvpn_ip(),
            'port': self.port,
            'platform': platform.system(),
            'status': 'Aguardando conexão',
        }
    def set_peer(self, p):
        self.peer = p
        self.peer_fingerprint = fingerprint(p['id_bytes'])
        self.service.set_expected_peer(p['id_bytes'])
    def connect(self):
        if not self.peer: raise ValueError('Adicione um contato primeiro.')
        # Usar o ConnectionManager para tentar múltiplos transportes
        self.connection_manager.connect(self.peer)
    def cancel_connect(self):
        """Cancela a tentativa de conexão em andamento."""
        self.connection_manager.cancel()
    def poll(self):
        out=[]
        while True:
            try:
                e=self.events.get_nowait()
                if e[0] in ('file_progress',): out.append(e)
                elif e[0]=='file_received': out.append(e)
                elif e[0]=='bt_devices': out.append(e)
                else: out.append(e)
            except queue.Empty:break
        return out
    def get_settings(self):
        """Retorna as configurações atuais do usuário."""
        return dict(self.settings)
    def set_settings(self, new_settings: dict) -> None:
        """Atualiza e salva as configurações do usuário."""
        # Validar e mesclar com as configurações atuais
        if 'transports' in new_settings:
            tor_was_enabled = self.settings['transports'].get('tor', False)
            self.settings['transports'].update(new_settings['transports'])
            if self.settings['transports'].get('tor') and not tor_was_enabled and not self.tor.is_online():
                threading.Thread(target=self.tor.start, name="retrochat-tor-boot", daemon=True).start()
        if 'tcp' in new_settings and isinstance(new_settings['tcp'], dict):
            mode = new_settings['tcp'].get('mode', self.settings.get('tcp', {}).get('mode', 'standard'))
            if mode not in {'standard', 'radminvpn'}:
                raise ValueError('Modo TCP inválido.')
            self.settings.setdefault('tcp', {})['mode'] = mode
        if 'theme' in new_settings:
            self.settings['theme'] = new_settings['theme']
        save_settings(self.base, self.settings)
    def shutdown(self):
        self.http.stop()
        self.service.stop()
        self.tor.stop()
        self.bluetooth.stop()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--profile'); args=ap.parse_args()
    if not PYSIDE_OK:
        raise SystemExit('PySide6 + Qt WebEngine não estão instalados. Instale requirements.txt.')
    qt=QApplication(sys.argv)
    app=App(args.profile)
    window=RetroWindow(f'http://127.0.0.1:{app.web_port}/')
    window.show()
    qt.aboutToQuit.connect(app.shutdown)
    return qt.exec()
if __name__=='__main__': raise SystemExit(main())