from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import mimetypes
import os
import platform
import queue
import re
import socket
import struct
import sys
import threading
import urllib.parse
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
PREFIX = "RETROCHAT2."


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
    if not isinstance(blob, str) or not blob.strip().startswith(PREFIX):
        raise ValueError("Contato RetroChat inválido.")
    try:
        encoded = blob.strip().split(".", 1)[1]
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

    payload["id_bytes"] = public_key
    payload["host"] = host
    payload["port"] = port
    return payload


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


DEFAULT_PORT = 28473
MAX_FRAME = 512 * 1024
FILE_CHUNK = 48 * 1024
MAX_FILE_SIZE = 512 * 1024 * 1024


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

    def connect(self, host: str, port: int, expected: bytes) -> None:
        if not host:
            raise ValueError("O contato não contém um endereço de rede.")

        def runner():
            last_error = None
            for candidate_host, candidate_port in build_connect_candidates(host, int(port)):
                try:
                    self._client(candidate_host, candidate_port, bytes(expected))
                    return
                except Exception as exc:
                    last_error = exc
            if last_error is not None:
                self.events.put(("error", str(last_error)))
            else:
                self.events.put(("error", "Não foi possível estabelecer a conexão usando os endpoints disponíveis."))

        threading.Thread(
            target=runner,
            name="retrochat-connect",
            daemon=True,
        ).start()

    def _connect_with_candidates(self, host: str, port: int, expected: bytes):
        last_error = None
        for candidate_host, candidate_port in build_connect_candidates(host, port):
            try:
                return self._client_attempt(candidate_host, candidate_port, expected)
            except Exception as exc:  # pragma: no cover - fluxo de rede real
                last_error = exc
        if last_error is not None:
            raise last_error
        raise ConnectionError("Não foi possível estabelecer uma conexão usando nenhum endpoint disponível.")

    def _client_attempt(self, host: str, port: int, expected: bytes):
        sock: socket.socket | None = None
        try:
            self.events.put(("status", f"Conectando a {host}:{port}..."))
            sock = socket.create_connection((host, port), timeout=10)
            sock.settimeout(None)
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
            self.events.put(("online", f"TCP em {host}:{port}"))
            self._read_loop(conn)
            return True
        except Exception:
            _safe_socket_close(sock)
            raise

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

    def _client(self, host: str, port: int, expected: bytes) -> None:
        sock: socket.socket | None = None
        try:
            self.events.put(("status", f"Conectando a {host}:{port}..."))
            sock = socket.create_connection((host, port), timeout=10)
            sock.settimeout(None)
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
            self.events.put(("online", "TCP"))
            self._read_loop(conn)
        except Exception as exc:
            _safe_socket_close(sock)
            message = "Conexão encerrada." if _is_socket_closed_error(exc) else str(exc)
            self.events.put(("error", message))

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
                            "port": peer.get("port", 28473),
                        },
                        ensure_ascii=False,
                    ),
                )

            if self.path == "/api/connect":
                self.app.connect()
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


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved


def _stun_binding(stun_host: str, stun_port: int = 3478, timeout: float = 1.5):
    """Consulta um servidor STUN e retorna o endpoint público mapeado pela NAT."""
    if not stun_host:
        return None
    try:
        msg = b"\x00\x01\x00\x00" + struct.pack("!I", 0x2112A442) + os.urandom(12)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (stun_host, int(stun_port)))
        data, _ = sock.recvfrom(2048)
        sock.close()
    except (OSError, socket.timeout):
        return None

    if len(data) < 20:
        return None
    try:
        msg_type = struct.unpack("!H", data[0:2])[0]
        if msg_type != 0x0101:
            return None
        length = struct.unpack("!H", data[2:4])[0]
        if len(data) < 20 + length:
            return None
        pos = 20
        while pos + 4 <= len(data):
            attr_type, attr_len = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            value = data[pos:pos + attr_len]
            pos += attr_len
            if attr_type == 0x0020 and len(value) >= 8:
                family = value[1]
                if family == 0x01:
                    xor_port = struct.unpack("!H", value[2:4])[0]
                    xor_ip = struct.unpack("!I", value[4:8])[0]
                    port = xor_port ^ ((0x2112A442 >> 16) & 0xFFFF)
                    ip_int = xor_ip ^ 0x2112A442
                    return socket.inet_ntoa(struct.pack("!I", ip_int)), int(port)
    except Exception:
        return None
    return None


def resolve_public_endpoint(host: str | None = None, port: int = DEFAULT_PORT, timeout: float = 1.5):
    """Tenta descobrir um endpoint público para conectar mesmo atrás de NAT/CGNAT."""
    if host and not _is_private_ip(host):
        return host, int(port)
    stun_servers = [
        os.environ.get("RETROCHAT_STUN_HOST", "stun.l.google.com"),
        "stun1.l.google.com",
        "stun.cloudflare.com",
    ]
    for stun_host in stun_servers:
        result = _stun_binding(stun_host, 3478, timeout=timeout)
        if result:
            return result
    return host or local_ip(), int(port)


def build_connect_candidates(host: str, port: int):
    """Ordena uma sequência de tentativas de conexão para NAT/CGNAT, começando pelo host direto."""
    seen = set()
    candidates = []
    hinted = [
        (host or local_ip(), int(port)),
        (resolve_public_endpoint(host, port)[0], resolve_public_endpoint(host, port)[1]),
    ]
    if os.environ.get("RETROCHAT_RELAY_HOST"):
        relay_port = int(os.environ.get("RETROCHAT_RELAY_PORT", "28474"))
        hinted.append((os.environ["RETROCHAT_RELAY_HOST"], relay_port))
    for candidate_host, candidate_port in hinted:
        key = (str(candidate_host), int(candidate_port))
        if key in seen:
            continue
        seen.add(key)
        candidates.append((str(candidate_host), int(candidate_port)))
    return candidates


class App:
    def __init__(self, profile=None):
        self.base=data_dir(profile); self.base.mkdir(parents=True,exist_ok=True); self.download_dir=self.base/'Downloads'; self.download_dir.mkdir(exist_ok=True); self.temp_dir=self.base/'tmp'; self.temp_dir.mkdir(exist_ok=True)
        self.identity = Identity.load_or_create(self.base / 'identity.key')
        self.events = queue.Queue()
        requested_port = int(os.environ.get('RETROCHAT_PORT', DEFAULT_PORT))
        self.service = PeerService(self.identity, requested_port, self.events, self.download_dir)
        self.service.start()
        self.port = self.service.port
        self.peer = None
        self.peer_fingerprint = ''
        self.bluetooth = BluetoothManager(self.events)
        self.bluetooth.start()
        self.http = ApiServer(self)
        self.web_port = self.http.start()
        self.html = HTML
    def info(self):
        host=local_ip()
        relay_host = os.environ.get('RETROCHAT_RELAY_HOST')
        relay_port = int(os.environ.get('RETROCHAT_RELAY_PORT', DEFAULT_PORT))
        if relay_host:
            contact_host, contact_port = relay_host, relay_port
        else:
            try:
                contact_host, contact_port = resolve_public_endpoint(host, self.port, timeout=1.0)
            except Exception:
                contact_host, contact_port = host, self.port
        return {
            'fingerprint': self.identity.fingerprint,
            'contact': self.identity.contact_blob(contact_host, contact_port),
            'host': host,
            'port': self.port,
            'platform': platform.system(),
            'status': 'Aguardando conexão',
            'nat': {
                'public_ip': contact_host,
                'public_port': contact_port,
                'relay': relay_host,
            },
        }
    def set_peer(self, p):
        self.peer = p
        self.peer_fingerprint = fingerprint(p['id_bytes'])
        self.service.set_expected_peer(p['id_bytes'])
    def connect(self):
        if not self.peer: raise ValueError('Adicione um contato primeiro.')
        host = self.peer.get('host') or ''
        port = int(self.peer.get('port') or DEFAULT_PORT)
        self.service.connect(host, port, self.peer['id_bytes'])
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
    def shutdown(self):
        self.http.stop()
        self.service.stop()
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