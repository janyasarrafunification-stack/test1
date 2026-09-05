import sys
import requests
import base64
import socket
import time
import concurrent.futures
import re
import os
import json
import subprocess
import tempfile
import stat
import logging
import threading
import hashlib
import hmac
import zlib
import urllib3
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, unquote, parse_qs
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RUN_START = time.time()

# ─────────────────────────────────────────────────────────────────────────────
# HTTP-сессии
# ─────────────────────────────────────────────────────────────────────────────
# SESSION — только для ПРЯМЫХ запросов (источники, GitHub API, Cloudflare без прокси).
# Для запросов ЧЕРЕЗ Xray-прокси используется одноразовая proxy_session():
# общая сессия кэширует ProxyManager на каждый 127.0.0.1:<port> навсегда
# (утечка памяти/дескрипторов) и ретраит 502/503 от мёртвого туннеля.
UA = "V1A-Scanner/1.2"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA})
_retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=64, pool_maxsize=64)
SESSION.mount("https://", _adapter)
SESSION.mount("http://", _adapter)


def proxy_session():
    """Изолированная сессия для одного Xray-теста: без ретраев, маленький пул."""
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    a = HTTPAdapter(max_retries=0, pool_connections=2, pool_maxsize=4)
    s.mount("https://", a)
    s.mount("http://", a)
    return s


# ─────────────────────────────────────────────────────────────────────────────
# ЛОГИРОВАНИЕ
# ─────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("V1A_Scanner")
logger.setLevel(logging.INFO)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(_h)

# ─────────────────────────────────────────────────────────────────────────────
# НАСТРОЙКИ
# ─────────────────────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.getenv("TOKEN", "")

SOURCES = [
    # --- Базовые источники ---
    "https://github.com/willafrid/skorodum.vpn/blob/main/cron-base64/combined.txt",
    "https://github.com/Maskkost93/kizyak-vpn-4.0/blob/main/kizyakbeta6BL.txt",
    "https://github.com/Maskkost93/kizyak-vpn-4.0/blob/main/kizyakbeta6.txt",
    "https://github.com/demian552010/NeVPN/blob/main/working_configs.txt",
    "https://github.com/svinakraft-maker/FlareFeed/blob/main/public/fastest.txt",
    "https://github.com/myominn062-svg/mk-studio-vpn-service/blob/main/mixed-protocol-chunks/MK-Studio-Mixed-Config-001.txt",
    "https://github.com/miladtahanian/Config-Collector/blob/main/mixed_iran.txt",
    "https://github.com/mmbcfgklmnm/-vpn-config-collector2/blob/main/configs/valid.txt",
    "https://github.com/zinted-vpn/Zinted-VPN/blob/main/Zinted%20VPN.txt",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/WhiteKeys",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt",
]

XRAY_BIN = "./xray"
OUTPUT_FILE = 'subscription'          # локальная копия: состояние «старых» узлов + публикация в режиме 1 репо
JSON_FILE = 'stats.json'
HISTORY_FILE = 'stats_history.json'
COUNTRIES_FILE = 'countries.json'
LOCAL_SOURCE_FILE = 'my_source'
META_FILE = 'run_meta.json'           # nodes/prev_nodes/bytes — для sanity-check в воркфлоу

# ─────────────────────────────────────────────────────────────────────────────
# 🔐 КЛЮЧИ. В GitHub Actions задаются через Secrets (env V1A_SUB_KEY / V1A_HISTORY_KEY).
# Дефолты ниже — ТОЛЬКО для локального запуска. В публичном репо ключ не хранить:
# зашей V1A_SUB_KEY в клиентскую программу, в репо оставь секрет.
# ─────────────────────────────────────────────────────────────────────────────
SUB_KEY = os.getenv("V1A_SUB_KEY", "V1A-Sub-Default-CHANGE-ME")
HISTORY_KEY = os.getenv("V1A_HISTORY_KEY", "V1A-History-Secret-2026")
SEAL_MAGIC = "V1A2."                  # маркер нового формата контейнера

# Старый формат подписки (читается один раз при миграции, потом можно удалить)
_LEGACY_SALT = "V1A"
_LEGACY_SHIFT = 7

# ─────────────────────────────────────────────────────────────────────────────
# 📤 ПУБЛИКАЦИЯ РЕЗУЛЬТАТА
# ─────────────────────────────────────────────────────────────────────────────
# РЕЖИМ 1 (сейчас): один репозиторий. Скрипт пишет OUTPUT_FILE, воркфлоу коммитит.
PUBLISH_TARGET = None

# РЕЖИМ 2 (будущее): отдельный аккаунт/репозиторий только для готового файла.
# Чтобы включить: закомментируй строку выше, раскомментируй блок ниже,
# и добавь в Secrets тестового репо секрет V1A_PUBLISH_TOKEN — fine-grained PAT
# от ДРУГОГО аккаунта с правом Contents: Read and write на ОДИН репо публикации.
# Локальный OUTPUT_FILE продолжает писаться (он нужен как состояние для
# следующего прогона), но клиентам отдаётся файл из репо публикации:
#   https://raw.githubusercontent.com/<repo>/<branch>/<path>
# PUBLISH_TARGET = {
#     "repo":      "other-account/vpn-public",   # владелец/репозиторий публикации
#     "branch":    "main",
#     "path":      "subscription",               # путь к файлу внутри репо
#     "token_env": "V1A_PUBLISH_TOKEN",          # имя переменной окружения с токеном
# }

ENABLED_PROTOCOLS = {
    "vless",
    # "vmess",
    # "trojan",
    "shadowsocks",
    "hysteria2",
}

LINK_PROTO_NAMES = {
    "vless": "vless", "vmess": "vmess", "trojan": "trojan",
    "ss": "shadowsocks", "hysteria2": "hysteria2", "hy2": "hysteria2",
}

# Hysteria2 с insecure=1 (самоподписанный сертификат) невозможно проверить в
# Xray >= v25 без pinnedPeerCertSha256 — такие ссылки пропускаем сразу,
# чтобы не тратить Xray-тест на гарантированный отказ.
HY2_SKIP_INSECURE = os.getenv("V1A_HY2_SKIP_INSECURE", "1") == "1"

# --- Параллельность ---
MAX_WORKERS = int(os.getenv("V1A_WORKERS", "64"))              # Xray-тестов в STAGE 1
STAGE2_WORKERS = int(os.getenv("V1A_STAGE2_WORKERS", "48"))    # Xray-тестов в STAGE 2
PING_WORKERS = int(os.getenv("V1A_PING_WORKERS", "400"))       # TCP-пинг (IO-bound)
# Одновременных закачек 5 МБ. Канал раннера делится между ними: чем больше,
# тем сильнее занижается скорость и тем больше ложных отказов по порогу.
SPEED_CONCURRENCY = int(os.getenv("V1A_SPEED_CONCURRENCY", "6"))
_speed_semaphore = threading.BoundedSemaphore(SPEED_CONCURRENCY)

# --- Таймауты ---
TCP_TIMEOUT = 2.5
REAL_TEST_TIMEOUT = 4.0
SPEED_TEST_TIMEOUT = 4.5
XRAY_START_TIMEOUT = 3.0
PING_ATTEMPTS = int(os.getenv("V1A_PING_ATTEMPTS", "2"))
SOURCE_WAIT_SEC = int(os.getenv("V1A_SOURCE_WAIT", "40"))
YT_CHECK_ENABLED = os.getenv("V1A_YT_CHECK", "1") == "1"

# --- Бюджет времени всего прогона ---
# STAGE 1 автоматически ужимается так, чтобы осталось STAGE2_RESERVE_SEC.
RUN_BUDGET_SEC = int(os.getenv("V1A_RUN_BUDGET_SEC", "1500"))       # 25 мин
STAGE1_MAX_SECONDS = int(os.getenv("V1A_STAGE1_MAX_SEC", "1000"))
STAGE2_RESERVE_SEC = int(os.getenv("V1A_STAGE2_RESERVE_SEC", "300"))
STAGE1_MAX_CANDIDATES = int(os.getenv("V1A_STAGE1_MAX_CANDIDATES", "9000"))

# --- Отбор ---
SPEED_HARD_LIMIT = 5.0                       # Mbps
MAX_SUBSCRIPTION_SERVERS = 1200
SPEED_CHECK_INTERVAL = 8 * 3600              # скорость старых — раз в 8 часов
# Грейс: старый узел выкидывается только после GRACE_MISSES+1 неудач ПОДРЯД.
GRACE_MISSES = int(os.getenv("V1A_GRACE_MISSES", "2"))
HISTORY_TTL_DAYS = int(os.getenv("V1A_HISTORY_TTL_DAYS", "14"))
# Предохранитель: если узлов получилось меньше N% от прошлой подписки — это сбой
# (сеть, Xray, проверка протоколов), файлы состояния НЕ перезаписываем.
MIN_RESULT_RATIO_PCT = int(os.getenv("V1A_MIN_RATIO_PCT", "30"))

SPEED_TEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes=5000000",
    "https://cachefly.cachefly.net/5mb.test",
    "https://proof.ovh.net/files/5Mb.dat",
]
MAX_SOURCE_CHARS = 15_000_000

COUNTRIES_RU = {}
try:
    if os.path.exists(COUNTRIES_FILE):
        with open(COUNTRIES_FILE, 'r', encoding='utf-8') as f:
            COUNTRIES_RU = json.load(f)
    else:
        logger.warning(f"⚠️ Файл {COUNTRIES_FILE} не найден! Страны будут кодами.")
except Exception as e:
    logger.error(f"❌ Ошибка загрузки {COUNTRIES_FILE}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# 🔐 ЗАЩИТА ФАЙЛОВ
# ─────────────────────────────────────────────────────────────────────────────
# Схема (без криптобиблиотек — только sha256/hmac/zlib/XOR):
#   key32 = SHA256(секрет)
#   nonce = 12 случайных байт                      -> каждый файл уникален
#   data  = zlib(plaintext)                        -> в 5-8 раз меньше, структура скрыта
#   ks[i] = SHA256(key32 ‖ nonce ‖ counter_i)      -> поток ключа
#   ct    = data XOR ks
#   tag   = HMAC-SHA256(key32, nonce ‖ ct)[:16]    -> проверка ключа и целостности
#   файл  = "V1A2." + base64url(nonce ‖ tag ‖ ct)
# С неверным ключом клиент получает внятную ошибку, а не мусор.
def _keystream(key32: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < length:
        out += hashlib.sha256(key32 + nonce + i.to_bytes(4, "big")).digest()
        i += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    # через int — на порядки быстрее побайтового цикла на мегабайтных файлах
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def seal(text: str, key: str) -> str:
    k = hashlib.sha256(key.encode("utf-8")).digest()
    nonce = os.urandom(12)
    data = zlib.compress(text.encode("utf-8"), 9)
    ct = _xor(data, _keystream(k, nonce, len(data)))
    tag = hmac.new(k, nonce + ct, hashlib.sha256).digest()[:16]
    return SEAL_MAGIC + base64.urlsafe_b64encode(nonce + tag + ct).decode("ascii").rstrip("=")


def unseal(token: str, key: str) -> str:
    if not token.startswith(SEAL_MAGIC):
        raise ValueError("not a V1A2 container")
    body = token[len(SEAL_MAGIC):]
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
    k = hashlib.sha256(key.encode("utf-8")).digest()
    if not hmac.compare_digest(tag, hmac.new(k, nonce + ct, hashlib.sha256).digest()[:16]):
        raise ValueError("wrong key or corrupted file")
    return zlib.decompress(_xor(ct, _keystream(k, nonce, len(ct)))).decode("utf-8")


def _legacy_deobfuscate(token: str) -> str:
    body = token[len(_LEGACY_SALT):] if token.startswith(_LEGACY_SALT) else token
    n = _LEGACY_SHIFT % max(len(body), 1)
    unshifted = body[n:] + body[:n] if n > 0 else body
    rev = unshifted[::-1]
    return base64.urlsafe_b64decode(rev + "=" * (-len(rev) % 4)).decode("utf-8")


def _legacy_decrypt_history(token: str):
    key = HISTORY_KEY
    xored = base64.urlsafe_b64decode(token).decode("utf-8")
    b64 = "".join(chr(ord(ch) ^ ord(key[i % len(key)])) for i, ch in enumerate(xored))
    return json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))


def open_subscription_text(token: str) -> str:
    """Новый формат -> старый формат -> как есть (ручная правка)."""
    token = token.strip()
    if token.startswith(SEAL_MAGIC):
        return unseal(token, SUB_KEY)
    try:
        return _legacy_deobfuscate(token)
    except Exception:
        return token


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            token = f.read().strip()
        if not token:
            return {}
        if token.startswith(SEAL_MAGIC):
            return json.loads(unseal(token, HISTORY_KEY))
        try:
            return _legacy_decrypt_history(token)
        except Exception:
            return json.loads(token)
    except Exception as e:
        logger.warning(f"⚠️ История не прочитана ({e}) — начинаем с пустой")
        return {}


def save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        f.write(seal(json.dumps(history, ensure_ascii=False, separators=(",", ":")), HISTORY_KEY))


# ─────────────────────────────────────────────────────────────────────────────
# 📤 ПУБЛИКАЦИЯ
# ─────────────────────────────────────────────────────────────────────────────
def publish_remote(content_text: str) -> bool:
    """Загружает готовый файл в другой репозиторий через GitHub Contents API.
    Работает через токен другого аккаунта — тестовый репо и репо публикации не связаны."""
    tgt = PUBLISH_TARGET
    token = os.getenv(tgt.get("token_env", "V1A_PUBLISH_TOKEN"), "")
    if not token:
        logger.error(f"❌ PUBLISH_TARGET задан, но переменная {tgt.get('token_env')} пуста — публикация пропущена")
        return False
    repo, branch, path = tgt["repo"], tgt.get("branch", "main"), tgt.get("path", "subscription")
    api = f"https://api.github.com/repos/{repo}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body_b64 = base64.b64encode(content_text.encode("utf-8")).decode("ascii")
    for attempt in range(1, 4):
        try:
            sha = None
            r = SESSION.get(api, headers=headers, params={"ref": branch}, timeout=20)
            if r.status_code == 200:
                sha = r.json().get("sha")
            elif r.status_code != 404:
                logger.warning(f"⚠️ Публикация: GET {r.status_code} {r.text[:200]}")
                time.sleep(2 * attempt)
                continue
            payload = {"message": f"Update: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
                       "content": body_b64, "branch": branch}
            if sha:
                payload["sha"] = sha
            r = SESSION.put(api, headers=headers, json=payload, timeout=60)
            if r.status_code in (200, 201):
                logger.info(f"📤 Опубликовано: https://raw.githubusercontent.com/{repo}/{branch}/{path}")
                return True
            if r.status_code == 409:          # sha устарел (параллельный коммит) — повтор
                time.sleep(2 * attempt)
                continue
            logger.error(f"❌ Публикация: PUT {r.status_code} {r.text[:300]}")
            return False
        except Exception as e:
            logger.warning(f"⚠️ Публикация, попытка {attempt}: {e}")
            time.sleep(2 * attempt)
    return False


def publish_subscription(sealed_text: str):
    # Локальная копия пишется ВСЕГДА: это состояние «старых» узлов для следующего прогона
    # (и публикуемый файл в режиме одного репозитория).
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(sealed_text)
    if PUBLISH_TARGET:
        if not publish_remote(sealed_text):
            logger.error("❌ Удалённая публикация не удалась — клиенты увидят прошлую версию файла")
    else:
        logger.info(f"💾 Режим одного репозитория: {OUTPUT_FILE} закоммитит воркфлоу")


def write_meta(nodes: int, prev_nodes: int, size_bytes: int):
    """Метаданные прогона для sanity-check в воркфлоу (размер файла в байтах
    сравнивать нельзя: сжатый V1A2-формат в разы меньше старого)."""
    try:
        with open(META_FILE, "w", encoding="utf-8") as f:
            json.dump({"nodes": nodes, "prev_nodes": prev_nodes, "bytes": size_bytes,
                       "ts": int(time.time())}, f)
    except Exception as e:
        logger.warning(f"⚠️ Не удалось записать {META_FILE}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# ИСТОРИЯ УЗЛОВ
# ─────────────────────────────────────────────────────────────────────────────
def node_id_of(server):
    return f"{server['ip']}:{server['port']}"


def hist_entry(history, node_id):
    e = history.get(node_id)
    if e is None:
        e = {}
        history[node_id] = e
    e.setdefault("streak", 0)
    e.setdefault("failures", 0)
    e.setdefault("misses", 0)
    e.setdefault("last_speed_check", 0)
    e.setdefault("last_seen", int(time.time()))
    return e


def mark_success(history, server, speed_checked):
    """Узел жив. speed_checked=True — скорость измерена в этом прогоне."""
    e = hist_entry(history, node_id_of(server))
    e["misses"] = 0
    e["last_seen"] = int(time.time())
    ok = server.get('speed_mbps', 0) >= SPEED_HARD_LIMIT
    if speed_checked:
        e["last_speed_check"] = int(time.time())
    if ok:
        e["streak"] += 1
        e["failures"] = max(0, e["failures"] - 1)
    else:
        e["streak"] = 0
        e["failures"] += 1


def mark_failure(history, server):
    """Узел не прошёл проверку. True — ещё в грейс-периоде."""
    e = hist_entry(history, node_id_of(server))
    e["misses"] += 1
    e["failures"] += 1
    e["streak"] = 0
    return e["misses"] <= GRACE_MISSES


def _last_seen_ts(v):
    if isinstance(v, (int, float)):
        return float(v)
    try:  # старый формат "YYYY-MM-DD"
        return datetime.strptime(str(v), "%Y-%m-%d").timestamp()
    except Exception:
        return time.time()


def prune_history(history):
    cutoff = time.time() - HISTORY_TTL_DAYS * 86400
    dead = [k for k, e in history.items() if _last_seen_ts(e.get("last_seen", 0)) < cutoff]
    for k in dead:
        history.pop(k, None)
    return len(dead)


def speed_due_for_check(history, node_id):
    last = history.get(node_id, {}).get('last_speed_check', 0)
    return (time.time() - last) >= SPEED_CHECK_INTERVAL


# ─────────────────────────────────────────────────────────────────────────────
# ПАРСЕРЫ
# ─────────────────────────────────────────────────────────────────────────────
def safe_base64_decode(s):
    s = s.strip().replace('\n', '').replace('\r', '').replace(' ', '')
    try:
        return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', errors='ignore')
    except Exception:
        try:
            return base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', errors='ignore')
        except Exception:
            return ""


def _base_server(proto, host, port, uuid, original, **kw):
    d = {
        "protocol": proto, "ip": host, "port": int(port), "uuid": uuid,
        "type": "tcp", "security": "none", "flow": "", "sni": "", "pbk": "", "sid": "", "spx": "/",
        "path": "/", "host": "", "fp": "chrome", "serviceName": "", "mode": "", "authority": "",
        "extra": "", "original": original, "country": "XX", "real_delay": 9999, "speed_mbps": 0.0,
    }
    d.update(kw)
    return d


def _split_hostport(hp):
    host, port = hp.rsplit(":", 1)
    return host.replace("[", "").replace("]", ""), int(port)


def parse_vless(config_str):
    try:
        full = config_str.strip()
        body = full.split('#', 1)[0]          # фрагмент отрезаем ДО разбора порта
        uuid_val = body.split("@", 1)[0][8:]
        rest = body.split("@", 1)[1]
        hp, _, query = rest.partition("?")
        host, port = _split_hostport(hp)
        p = parse_qs(query) if query else {}
        g = lambda k, d='': p.get(k, [d])[0]
        conf = _base_server("vless", host, port, uuid_val, full,
                            type=g('type', 'tcp'), security=g('security', 'none'), flow=g('flow'),
                            sni=g('sni'), pbk=g('pbk'), sid=g('sid'), spx=g('spx', '/'), path=g('path', '/'),
                            host=g('host'), fp=g('fp', 'chrome'), serviceName=g('serviceName'),
                            mode=g('mode'), authority=g('authority'), extra=g('extra'))
        if conf['security'] == 'reality' and not conf['pbk']:
            return None
        return conf
    except Exception:
        return None


def parse_trojan(config_str):
    try:
        full = config_str.strip()
        body = full.split('#', 1)[0]
        password = body.split("@", 1)[0][9:]
        rest = body.split("@", 1)[1]
        hp, _, query = rest.partition("?")
        host, port = _split_hostport(hp)
        p = parse_qs(query) if query else {}
        g = lambda k, d='': p.get(k, [d])[0]
        return _base_server("trojan", host, port, password, full,
                            type=g('type', 'tcp'), security=g('security', 'none'), sni=g('sni'),
                            path=g('path', '/'), host=g('host'), fp=g('fp', 'chrome'),
                            serviceName=g('serviceName'), mode=g('mode'), authority=g('authority'),
                            extra=g('extra'))
    except Exception:
        return None


def parse_vmess(config_str):
    try:
        full = config_str.strip()
        b64_str = full[8:].split('#', 1)[0]
        json_str = safe_base64_decode(b64_str)
        if not json_str:
            return None
        data = json.loads(json_str)
        return _base_server("vmess", data.get('add', ''), int(data.get('port', 443)), data.get('id', ''), full,
                            type=data.get('net', 'tcp'),
                            security="tls" if data.get('tls', '') == 'tls' else "none",
                            sni=data.get('sni', data.get('host', '')), path=data.get('path', '/'),
                            host=data.get('host', ''), fp=data.get('fp', 'chrome'),
                            serviceName=data.get('serviceName', ''), mode=data.get('mode', ''),
                            authority=data.get('authority', ''), extra=data.get('extra', ''))
    except Exception:
        return None


def parse_shadowsocks(config_str):
    try:
        full = config_str.strip()
        body = full.split('://', 1)[1].split('#', 1)[0].split('?', 1)[0]
        if '@' in body:
            userinfo, hostport = body.rsplit('@', 1)
            if ':' not in userinfo:
                userinfo = safe_base64_decode(userinfo)
        else:
            dec = safe_base64_decode(body)
            if not dec or '@' not in dec:
                return None
            userinfo, hostport = dec.rsplit('@', 1)
        method, password = userinfo.split(':', 1)
        host, port = _split_hostport(hostport)
        return _base_server("shadowsocks", host, port, password, full, method=method)
    except Exception:
        return None


def parse_hysteria2(config_str):
    try:
        full = config_str.strip()
        body = full.split('://', 1)[1].split('#', 1)[0]
        if '@' not in body:
            return None
        password, rest = body.rsplit('@', 1)
        hostport, _, query = rest.partition('?')
        p = parse_qs(query) if query else {}
        g = lambda k, d='': p.get(k, [d])[0]
        if HY2_SKIP_INSECURE and (g('insecure', '0').lower() in ('1', 'true')
                                  or g('allowInsecure', '0').lower() in ('1', 'true')):
            return None
        host, port = _split_hostport(hostport)
        return _base_server("hysteria2", host, port, password, full,
                            type="udp", security="tls", sni=g('sni'), fp=g('fp', 'chrome'),
                            authority=g('authority'), extra=g('obfs-password'))
    except Exception:
        return None


def parse_link_into_server(link):
    try:
        link = link.strip()
        prefix = link.split('://', 1)[0].lower()
        proto = LINK_PROTO_NAMES.get(prefix)
        if proto not in ENABLED_PROTOCOLS:
            return None
        return {
            "vless": parse_vless, "trojan": parse_trojan, "vmess": parse_vmess,
            "shadowsocks": parse_shadowsocks, "hysteria2": parse_hysteria2,
        }[proto](link)
    except Exception:
        return None


def collect_parsed_servers(links):
    servers, seen, skipped = [], set(), 0
    for link in links:
        if not isinstance(link, str):
            skipped += 1
            continue
        link = link.strip()
        if not link or '://' not in link:
            skipped += 1
            continue
        if link in seen:
            continue
        seen.add(link)
        srv = parse_link_into_server(link)
        if srv:
            servers.append(srv)
        else:
            skipped += 1
    return servers, skipped


def extract_links(text):
    regex = r"(?i)(?<![\w])((?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\r\n\"'<>]+)"
    links = re.findall(regex, text)
    decoded = safe_base64_decode(text)
    if decoded:
        links.extend(re.findall(regex, decoded))
    for line in text.splitlines():
        dec_line = safe_base64_decode(line)
        if dec_line:
            links.extend(re.findall(regex, dec_line))
    return list(set(links))


def extract_ping_speed_from_link(server):
    orig = server.get('original', '')
    if '#' in orig:
        frag = unquote(orig.split('#', 1)[1])
        m = re.search(r'Speed:([\d.]+)', frag)
        if m:
            server['speed_mbps'] = float(m.group(1))
        m = re.search(r'Ping:(\d+)', frag)
        if m:
            server['real_delay'] = int(m.group(1))
    return server


def load_previous_subscription():
    servers = []
    if not os.path.exists(OUTPUT_FILE):
        logger.info("📂 Прошлого subscription нет — работаем только с новыми серверами.")
        return servers
    try:
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            token = f.read().strip()
        raw = open_subscription_text(token)
        seen = set()
        raw_count = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            srv = parse_link_into_server(line)
            if not srv:
                continue
            raw_count += 1
            nid = node_id_of(srv)
            if nid in seen:
                continue
            seen.add(nid)
            extract_ping_speed_from_link(srv)
            srv['from_prev'] = True
            servers.append(srv)
        logger.info(f"📂 Прошлый subscription: {len(servers)} уникальных серверов (строк: {raw_count}).")
    except Exception as e:
        logger.warning(f"⚠️ Не удалось прочитать прошлый subscription: {e}")
    return servers


# ─────────────────────────────────────────────────────────────────────────────
# XRAY
# ─────────────────────────────────────────────────────────────────────────────
def get_latest_xray_version():
    pinned = os.getenv("V1A_XRAY_VERSION", "").strip()
    if pinned:
        return pinned.lstrip("v")
    try:
        headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
        r = SESSION.get("https://api.github.com/repos/XTLS/Xray-core/releases/latest", headers=headers, timeout=8)
        if r.status_code == 200:
            tag = r.json().get("tag_name", "")
            if tag:
                return tag.lstrip("v")
    except Exception:
        pass
    logger.warning("⚠️ GitHub API недоступен — использую резервную версию Xray 26.3.27")
    return "26.3.27"


def install_xray_core():
    import zipfile, io
    desired_version = get_latest_xray_version()
    if os.path.exists(XRAY_BIN):
        st = os.stat(XRAY_BIN)
        if not (st.st_mode & stat.S_IEXEC):
            try:
                os.chmod(XRAY_BIN, st.st_mode | stat.S_IEXEC)
            except Exception as e:
                logger.warning(f"⚠️ Ошибка выдачи прав Xray: {e}")
        try:
            result = subprocess.run([XRAY_BIN, "version"], capture_output=True, text=True, timeout=2)
            if desired_version in result.stdout:
                return
            # Бинарник рабочий, но версия другая: не удаляем, пока не скачаем новый
            logger.info(f"🔄 Xray {result.stdout.split()[1] if result.stdout else '?'} -> {desired_version}")
        except Exception:
            logger.info("🔄 Xray неисправен — переустанавливаем")

    logger.info(f"📥 Xray core ({desired_version}) скачивается...")
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{desired_version}/Xray-linux-64.zip"
    try:
        r = SESSION.get(url, timeout=60)
        if r.status_code != 200:
            logger.error(f"❌ Ошибка скачивания: HTTP {r.status_code} (оставляю текущий бинарник, если он есть)")
            return
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            if 'xray' not in z.namelist():
                logger.error("❌ В архиве нет файла xray!")
                return
            with z.open('xray') as zf, open(XRAY_BIN + ".new", 'wb') as f:
                f.write(zf.read())
        os.chmod(XRAY_BIN + ".new", 0o755)
        os.replace(XRAY_BIN + ".new", XRAY_BIN)
        logger.info("✅ Xray установлен успешно.")
    except Exception as e:
        logger.error(f"❌ Критическая ошибка установки Xray: {e}")


_XRAY_PROTO_OK = {}
# Маркеры в выводе xray, означающие именно ОТСУТСТВИЕ протокола/транспорта в сборке.
# Любая другая ошибка (кривой пробный конфиг, «vnext is empty» и т. п.) протокол НЕ отключает.
_UNSUPPORTED_MARKERS = ("unknown config id", "unknown protocol", "unknown transport",
                        "unsupported protocol", "not supported")


def xray_supports_protocol(proto_internal):
    """`xray run -test` на ПОЛНОМ пробном конфиге, собранном generate_xray_config
    (тем же кодом, что и боевые тесты). Раньше конфиг был с пустыми settings,
    Xray падал на сборке и ВСЕ протоколы объявлялись неподдерживаемыми."""
    if proto_internal in _XRAY_PROTO_OK:
        return _XRAY_PROTO_OK[proto_internal]
    dummy_uuid = "00000000-0000-0000-0000-000000000000"
    if proto_internal == "hysteria2":
        fake = _base_server("hysteria2", "127.0.0.1", 443, dummy_uuid, "",
                            type="udp", security="tls", sni="example.com")
    elif proto_internal == "shadowsocks":
        fake = _base_server("shadowsocks", "127.0.0.1", 8388, "password", "", method="aes-256-gcm")
    else:  # vless / vmess / trojan
        fake = _base_server(proto_internal, "127.0.0.1", 443, dummy_uuid, "",
                            security="tls", sni="example.com")
    ok, path, port = True, None, get_free_port()
    try:
        cfg = generate_xray_config(fake, port)
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
            json.dump(cfg, tmp)
            path = tmp.name
        r = subprocess.run([XRAY_BIN, "run", "-c", path, "-test"], capture_output=True, text=True, timeout=8)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        if r.returncode != 0:
            if any(m in out.lower() for m in _UNSUPPORTED_MARKERS):
                ok = False
                logger.info(f"ℹ️ Xray без поддержки {proto_internal}: {out[:160]}")
            else:
                logger.warning(f"⚠️ Пробный конфиг {proto_internal} не собрался (код {r.returncode}), "
                               f"протокол оставлен включённым: {out[:200]}")
    except Exception as e:
        logger.warning(f"⚠️ Проверка протокола {proto_internal} не выполнена ({e}) — считаю поддерживаемым")
    finally:
        release_port(port)
        if path:
            try:
                os.remove(path)
            except OSError:
                pass
    _XRAY_PROTO_OK[proto_internal] = ok
    return ok


_PORT_LOCK = threading.Lock()
_PORT_NEXT = 20000
_PORTS_IN_USE = set()


def get_free_port():
    global _PORT_NEXT
    with _PORT_LOCK:
        for _ in range(25000):
            port = _PORT_NEXT
            _PORT_NEXT += 1
            if _PORT_NEXT > 45000:
                _PORT_NEXT = 20000
            if port in _PORTS_IN_USE:
                continue
            probe = socket.socket()
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            finally:
                probe.close()
            _PORTS_IN_USE.add(port)
            return port
    with socket.socket() as s:
        s.bind(("", 0))
        port = s.getsockname()[1]
    with _PORT_LOCK:
        _PORTS_IN_USE.add(port)
    return port


def release_port(port):
    with _PORT_LOCK:
        _PORTS_IN_USE.discard(port)


def wait_xray_ready(proc, port, timeout=XRAY_START_TIMEOUT):
    """Ждём открытия порта; если процесс умер (кривой конфиг) — сразу False."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _wrap_config(outbound, local_port):
    return {"log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "http"}],
            "outbounds": [outbound]}


def generate_xray_config(server, local_port):
    xray_proto = "hysteria" if server['protocol'] == 'hysteria2' else server['protocol']
    outbound = {"protocol": xray_proto, "settings": {},
                "streamSettings": {"network": server['type'], "security": server['security']}}

    if server['protocol'] == 'vless':
        user = {"id": server['uuid'], "encryption": "none"}
        flow = server.get('flow', '')
        if flow and server['type'] in ('tcp', 'h2', 'http'):
            user['flow'] = flow
        outbound['settings'] = {"vnext": [{"address": server['ip'], "port": server['port'], "users": [user]}]}
    elif server['protocol'] == 'trojan':
        outbound['settings'] = {"servers": [{"address": server['ip'], "port": server['port'], "password": server['uuid']}]}
    elif server['protocol'] == 'shadowsocks':
        outbound['settings'] = {"servers": [{"address": server['ip'], "port": server['port'],
                                             "method": server.get('method', 'aes-256-gcm'), "password": server['uuid']}]}
    elif server['protocol'] == 'hysteria2':
        outbound['settings'] = {"version": 2, "address": server['ip'], "port": server['port']}
    else:  # vmess
        outbound['settings'] = {"vnext": [{"address": server['ip'], "port": server['port'],
                                           "users": [{"id": server['uuid'], "alterId": 0, "security": "auto"}]}]}

    path = server.get('path', '/') or '/'
    if not path.startswith('/'):
        path = '/' + path
    ss = outbound["streamSettings"]
    t = server['type']

    if server['protocol'] == 'hysteria2':
        outbound['streamSettings'] = {
            "network": "hysteria", "security": "tls",
            "tlsSettings": {"serverName": server.get('sni') or server['ip'], "fingerprint": server.get('fp', 'chrome')},
            "hysteriaSettings": {"version": 2, "auth": server['uuid'], "udpIdleTimeout": 60},
        }
        return _wrap_config(outbound, local_port)
    elif t == 'ws':
        ws = {"path": path}
        if server.get('host'):
            ws["headers"] = {"Host": server['host']}
        ss["wsSettings"] = ws
    elif t == 'grpc':
        g = {"serviceName": server.get('serviceName', '')}
        if server.get('authority'):
            g["authority"] = server['authority']
        ss["grpcSettings"] = g
    elif t in ('xhttp', 'splithttp'):
        x = {"path": path}
        if server.get('host'):
            x["host"] = server['host']
        if server.get('mode'):
            x["mode"] = server['mode']
        extra_str = server.get('extra', '')
        if extra_str:
            extra_dict = {}
            if extra_str.startswith('{') and extra_str.endswith('}'):
                try:
                    extra_dict = json.loads(extra_str)
                except Exception:
                    for pair in extra_str[1:-1].split(','):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            extra_dict[k.strip()] = v.strip()
            elif '=' in extra_str:
                for pair in extra_str.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        extra_dict[k.strip()] = v.strip()
            if extra_dict:
                x["extra"] = extra_dict
        ss["network"] = "xhttp"
        ss["xhttpSettings"] = x
    elif t == 'httpupgrade':
        h = {"path": path}
        if server.get('host'):
            h["host"] = server['host']
        ss["httpupgradeSettings"] = h
    elif t in ('h2', 'http'):
        h = {"path": path}
        if server.get('host'):
            h["host"] = [server['host']]
        ss["network"] = "h2"
        ss["httpSettings"] = h

    tls_set = {"serverName": server.get('sni', ''), "fingerprint": server.get('fp', 'chrome')}
    if server['security'] == 'tls':
        ss["tlsSettings"] = tls_set
    elif server['security'] == 'reality':
        r = dict(tls_set)
        r.update({"show": False, "publicKey": server.get('pbk', ''),
                  "shortId": server.get('sid', ''), "spiderX": server.get('spx', '/')})
        ss["realitySettings"] = r
    return _wrap_config(outbound, local_port)


class XrayTunnel:
    """Контекст: конфиг во временный файл, запуск Xray, ожидание порта, уборка."""

    def __init__(self, server):
        self.server = server
        self.port = None
        self.path = None
        self.proc = None
        self.ready = False

    def __enter__(self):
        self.port = get_free_port()
        cfg = generate_xray_config(self.server, self.port)
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
            json.dump(cfg, tmp)
            self.path = tmp.name
        self.proc = subprocess.Popen([XRAY_BIN, "-c", self.path],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.ready = wait_xray_ready(self.proc, self.port)
        return self

    @property
    def proxies(self):
        return {"http": f"http://127.0.0.1:{self.port}", "https": f"http://127.0.0.1:{self.port}"}

    def __exit__(self, *exc):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=0.5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        if self.path:
            try:
                os.remove(self.path)
            except OSError:
                pass
        if self.port is not None:
            release_port(self.port)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# ПРОВЕРКИ
# ─────────────────────────────────────────────────────────────────────────────
def get_accurate_ping(ip, port, attempts=3):
    lat = []
    for _ in range(attempts):
        try:
            t0 = time.perf_counter()
            with socket.create_connection((ip, port), timeout=2.0):
                lat.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
        time.sleep(0.05)
    if not lat:
        return 9999
    if len(lat) >= 3:
        lat.remove(max(lat))
    return int(sum(lat) / len(lat))


def ping_filter(server):
    for _ in range(max(1, PING_ATTEMPTS)):
        try:
            t0 = time.perf_counter()
            with socket.create_connection((server['ip'], server['port']), timeout=TCP_TIMEOUT):
                server['tcp_ping_ms'] = int((time.perf_counter() - t0) * 1000)
                return server
        except Exception:
            continue
    return None


def cf_trace(sess, proxies, attempts=1):
    """(latency_ms, country) через туннель или (None, None)."""
    for i in range(attempts):
        try:
            t0 = time.perf_counter()
            r = sess.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=REAL_TEST_TIMEOUT)
            if r.status_code == 200:
                m = re.search(r'loc=([A-Z]{2})', r.text)
                return int((time.perf_counter() - t0) * 1000), (m.group(1) if m else 'XX')
        except Exception:
            pass
        if i + 1 < attempts:
            time.sleep(0.2)
    return None, None


def measure_download_speed(sess, proxies):
    with _speed_semaphore:
        for url in SPEED_TEST_URLS:
            resp = None
            try:
                resp = sess.get(url, proxies=proxies, timeout=(2.0, SPEED_TEST_TIMEOUT), stream=True)
                if resp.status_code != 200:
                    continue
                t0 = time.perf_counter()
                nbytes = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        nbytes += len(chunk)
                    if time.perf_counter() - t0 > SPEED_TEST_TIMEOUT:
                        break
                dur = time.perf_counter() - t0
                if dur > 0 and nbytes > 0:
                    return round((nbytes * 8 / 1_000_000) / dur, 2)
            except Exception:
                continue
            finally:
                if resp is not None:
                    try:
                        resp.close()
                    except Exception:
                        pass
        return 0.0


def deep_verify(server):
    """STAGE 1. -> (server, None) | (None, reason). Всё внутри try: поток не падает."""
    try:
        with XrayTunnel(server) as tun:
            if not tun.ready:
                return None, 'xray_start'
            with proxy_session() as ps:
                latency, country = cf_trace(ps, tun.proxies)
                if latency is None:
                    return None, 'trace_http'
                if YT_CHECK_ENABLED:
                    try:
                        yt = ps.get("https://www.youtube.com/generate_204", proxies=tun.proxies, timeout=3.0)
                        if yt.status_code != 204:
                            return None, 'yt_fail'
                    except Exception:
                        return None, 'yt_fail'
                speed = measure_download_speed(ps, tun.proxies)
        server['real_delay'] = latency
        server['country'] = country
        server['speed_mbps'] = speed
        return server, None
    except Exception:
        return None, 'xray_error'


_TRANSIENT_REASONS = {"trace_http", "xray_error", "xray_start"}


def deep_verify_with_retry(server):
    res, reason = deep_verify(server)
    if res is None and reason in _TRANSIENT_REASONS:
        time.sleep(0.3)
        res, reason = deep_verify(server)
    return res, reason


def measure_node_stats(server, check_speed=True):
    """STAGE 2. -> (server, ok). При неудаче поля сервера НЕ трогаем (нужно для грейса)."""
    try:
        tcp_ping = get_accurate_ping(server['ip'], server['port'], attempts=3)
        with XrayTunnel(server) as tun:
            if not tun.ready:
                return server, False
            with proxy_session() as ps:
                _, country = cf_trace(ps, tun.proxies, attempts=2)
                if country is None:
                    return server, False
                speed = measure_download_speed(ps, tun.proxies) if check_speed else 0.0
        server['country'] = country
        if tcp_ping != 9999:
            server['real_delay'] = tcp_ping
        if check_speed and speed > 0:
            server['speed_mbps'] = speed
        return server, True
    except Exception:
        return server, False


def calculate_quality_score(server, history):
    e = history.get(node_id_of(server), {})
    score = min(server.get('speed_mbps', 0) / 10.0, 1.0) * 40
    score += min(e.get("streak", 0) * 10, 30)
    score -= min(e.get("failures", 0) * 5, 20)
    if server['protocol'] in ('vless', 'trojan') and server.get('security') == 'reality':
        score += 20
    elif server['protocol'] in ('vless', 'trojan'):
        score += 15
    else:
        score += 5
    score -= min(server.get('real_delay', 1000) / 1000.0, 1.0) * 10
    return max(0, round(score, 1))


def get_speed_badge(s):
    if s >= 10.0: return "🚀 "
    if s >= 5.0: return "⚡⚡ "
    if s >= 1.5: return "⚡ "
    return "🐢 "


def detect_test_location():
    try:
        r = SESSION.get("https://cloudflare.com/cdn-cgi/trace", timeout=6)
        if r.status_code == 200:
            m = re.search(r'loc=([A-Z]{2})', r.text)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ИСТОЧНИКИ
# ─────────────────────────────────────────────────────────────────────────────
def fetch_source(url):
    try:
        resp = SESSION.get(url, timeout=(3, 10))
        if resp.status_code == 200:
            links = extract_links(resp.text[:MAX_SOURCE_CHARS])
            logger.info(f"📥 Источник {url[:48]}... -> {len(links)} ссылок")
            return links
        logger.warning(f"⚠️ Источник {url[:48]}...: HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"⚠️ Ошибка источника {url[:40]}...: {e}")
    return []


def search_github_configs():
    logger.info("🔍 Ищем свежие конфиги на GitHub (Live Search)...")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    links = []
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    for q in ("vless reality", "trojan proxy"):
        try:
            url = f"https://api.github.com/search/repositories?q={quote(q)}+pushed:>{since}&sort=updated"
            r = SESSION.get(url, headers=headers, timeout=8)
            if r.status_code != 200:
                continue
            for item in r.json().get('items', [])[:2]:
                readme = f"https://raw.githubusercontent.com/{item['full_name']}/{item['default_branch']}/README.md"
                try:
                    rr = SESSION.get(readme, timeout=10)
                    if rr.status_code == 200:
                        links.extend(extract_links(rr.text[:50000]))
                except Exception:
                    pass
        except Exception:
            pass
    return list(set(links))


def run_ping_stage(servers, label):
    t0 = time.time()
    alive, dead = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        fm = {ex.submit(ping_filter, s): s for s in servers}
        for f in concurrent.futures.as_completed(fm):
            try:
                res = f.result()
            except Exception:
                res = None
            (alive if res else dead).append(res or fm[f])
    logger.info(f"✅ {label}: живых {len(alive)} из {len(servers)} за {time.time() - t0:.0f} сек.")
    return alive, dead


def time_left():
    return RUN_BUDGET_SEC - (time.time() - RUN_START)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    logger.info("🚀 START: V1A Smart Selector")
    if SUB_KEY == "V1A-Sub-Default-CHANGE-ME":
        logger.warning("⚠️ V1A_SUB_KEY не задан — используется дефолтный ключ (только для локальной отладки!)")
    if PUBLISH_TARGET:
        logger.info(f"📤 Режим публикации: отдельный репозиторий {PUBLISH_TARGET['repo']}")

    test_loc = detect_test_location()
    if test_loc:
        logger.info(f"🛰 Регион тестирования: {COUNTRIES_RU.get(test_loc, test_loc)} ({test_loc}). "
                    f"Доступность из РФ может отличаться (DPI/РКН).")

    install_xray_core()
    if not os.path.exists(XRAY_BIN):
        logger.error(f"❌ Не удалось найти {XRAY_BIN}")
        sys.exit(1)

    enabled_list = sorted(ENABLED_PROTOCOLS)
    logger.info(f"🎛 Включённые протоколы: {', '.join(enabled_list)}")
    unsupported = [p for p in enabled_list if not xray_supports_protocol(p)]
    if unsupported and len(unsupported) == len(enabled_list):
        # Xray без VLESS не существует: если забраковано ВСЁ — сломана проверка, а не Xray.
        logger.error("❌ Проверка протоколов забраковала ВСЕ включённые протоколы — это сбой самой проверки. "
                     "Её результат игнорирую, тестирую всё.")
        unsupported = []
    elif unsupported:
        logger.warning(f"⚠️ Xray НЕ поддерживает: {', '.join(unsupported)} — их узлы будут пропущены.")

    history = load_history()

    # ── Старые серверы ──
    prev_servers = [s for s in load_previous_subscription() if s['protocol'] not in unsupported]
    prev_count = len(prev_servers)

    # ── Источники (параллельно, с лимитом ожидания) ──
    logger.info(f"🌐 Загрузка источников ({', '.join(enabled_list)})...")
    all_configs, total_skipped = [], 0
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    futures = [ex.submit(fetch_source, u) for u in dict.fromkeys(SOURCES)]
    futures.append(ex.submit(search_github_configs))
    done_set, not_done = concurrent.futures.wait(futures, timeout=SOURCE_WAIT_SEC)
    for f in not_done:
        f.cancel()
    slow = sum(1 for f in not_done if f.running())
    for f in done_set:
        try:
            servers, skipped = collect_parsed_servers(f.result())
            all_configs.extend(servers)
            total_skipped += skipped
        except Exception as e:
            logger.warning(f"⚠️ Ошибка обработки источника: {e}")
    ex.shutdown(wait=False, cancel_futures=True)
    if slow:
        logger.warning(f"⏳ Источников не дождались (> {SOURCE_WAIT_SEC} сек): {slow}")
    if total_skipped:
        logger.info(f"🧹 Пропущено пустых/невалидных ссылок: {total_skipped}")

    if os.path.exists(LOCAL_SOURCE_FILE):
        try:
            with open(LOCAL_SOURCE_FILE, "r", encoding="utf-8", errors="ignore") as lf:
                local_servers, _ = collect_parsed_servers(extract_links(lf.read()))
            all_configs.extend(local_servers)
            logger.info(f"📁 {LOCAL_SOURCE_FILE}: {len(local_servers)} серверов")
        except Exception as e:
            logger.error(f"❌ Ошибка чтения {LOCAL_SOURCE_FILE}: {e}")

    all_configs = [c for c in all_configs if c['protocol'] not in unsupported]
    fresh_by_id = {node_id_of(c): c for c in all_configs}
    logger.info(f"🔍 Уникальных конфигов из источников: {len(fresh_by_id)}")

    # Старый узел получает СВЕЖУЮ ссылку из источника (pbk/sid/path могли смениться),
    # но сохраняет накопленные пинг/скорость/метку from_prev.
    refreshed = 0
    for s in prev_servers:
        fr = fresh_by_id.get(node_id_of(s))
        if fr and fr['protocol'] == s['protocol']:
            keep = {k: s[k] for k in ('speed_mbps', 'real_delay', 'from_prev', 'country')}
            s.update(fr)
            s.update(keep)
            refreshed += 1
    if refreshed:
        logger.info(f"🔄 Старых узлов обновлено свежей ссылкой из источников: {refreshed}")

    # ── Пинг старых ──
    logger.info(f"⚡ Пинг старых серверов ({len(prev_servers)})...")
    alive_prev, dead_prev = run_ping_stage(prev_servers, "Старые")

    pool = []            # итоговые кандидаты в подписку
    handled_ids = set()  # ip:port, уже обработанные как «старые»

    # Мёртвые по пингу старые: грейс или окончательный отсев
    grace_dead = 0
    for s in dead_prev:
        if mark_failure(history, s) and s.get('speed_mbps', 0) >= SPEED_HARD_LIMIT:
            s['grace'] = True
            s['skip_speed'] = True
            pool.append(s)
            handled_ids.add(node_id_of(s))
            grace_dead += 1
    if grace_dead:
        logger.info(f"🕊 Старых не ответивших на пинг оставлено в грейс-периоде: {grace_dead}")

    # Живые старые: кого перепроверять по скорости
    prev_keep, prev_recheck = [], []
    for s in alive_prev:
        nid = node_id_of(s)
        handled_ids.add(nid)
        # Узлы со скоростью < порога (или без данных) — обязательно перепроверить
        if speed_due_for_check(history, nid) or s.get('speed_mbps', 0) < SPEED_HARD_LIMIT:
            prev_recheck.append(s)
        else:
            prev_keep.append(s)
    logger.info(f"   Старых с актуальной скоростью: {len(prev_keep)} | на перепроверку скорости: {len(prev_recheck)}")

    # ── STAGE 0: пинг новых (только тех, кого нет среди старых) ──
    fresh_candidates = [c for nid, c in fresh_by_id.items() if nid not in handled_ids]
    logger.info(f"⚡ ЭТАП 0: TCP-пинг новых. Кандидатов: {len(fresh_candidates)} "
                f"(совпали со старыми, не дублируем: {len(fresh_by_id) - len(fresh_candidates)})")
    new_alive, _ = run_ping_stage(fresh_candidates, "Новые")

    # ── STAGE 1: Xray-тест (старые на перепроверку + новые живые) — дублей нет ──
    to_test = prev_recheck + new_alive
    to_test.sort(key=lambda s: (0 if s.get('from_prev') else 1, s.get('tcp_ping_ms', 9999)))
    if len(to_test) > STAGE1_MAX_CANDIDATES:
        logger.info(f"⚖️ Кандидатов больше лимита {STAGE1_MAX_CANDIDATES}: отложено {len(to_test) - STAGE1_MAX_CANDIDATES}")
        to_test = to_test[:STAGE1_MAX_CANDIDATES]

    stage1_budget = max(60, min(STAGE1_MAX_SECONDS, time_left() - STAGE2_RESERVE_SEC))
    logger.info(f"⚡ ЭТАП 1: Xray-тест. Workers: {MAX_WORKERS}, кандидатов: {len(to_test)}, бюджет {stage1_budget:.0f} сек")
    t1 = time.time()
    deadline = t1 + stage1_budget
    tested, failed_prev, untested_prev = [], [], []
    fail_stats = {}
    processed = set()
    timed_out = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fm = {ex.submit(deep_verify_with_retry, s): s for s in to_test}
        done = 0
        for f in concurrent.futures.as_completed(fm):
            if time.time() > deadline:
                timed_out = True
                break
            done += 1
            s = fm[f]
            processed.add(f)
            try:
                res, reason = f.result()
            except Exception:
                res, reason = None, 'exception'
            if res:
                tested.append(res)
                logger.info(f"   [{res['country']}] {res['protocol'].upper()} | HTTP: {res['real_delay']}ms | {res['speed_mbps']} Mbps")
            else:
                fail_stats[reason] = fail_stats.get(reason, 0) + 1
                if s.get('from_prev'):
                    failed_prev.append(s)
            if done % 200 == 0 or done == len(to_test):
                el = time.time() - t1
                logger.info(f"   ⏱ STAGE 1: {done}/{len(to_test)} (прошло {len(tested)}), {el:.0f} сек, ~{done / max(el, 1):.1f}/сек")
        if timed_out:
            cancelled = sum(1 for f in fm if f.cancel())
            logger.warning(f"⏳ Бюджет STAGE 1 исчерпан: протестировано {done}, снято с очереди {cancelled}.")
        # Старые, которых не успели протестировать — НЕ считаем провалом, оставляем как есть
        for f, s in fm.items():
            if f not in processed and s.get('from_prev'):
                untested_prev.append(s)

    logger.info(f"📊 ЭТАП 1: {len(to_test)} кандидатов за {time.time() - t1:.0f} сек | прошло {len(tested)} | "
                f"отсев: {', '.join(f'{k}={v}' for k, v in sorted(fail_stats.items())) or '—'}")

    # ── Сборка пула ──
    for s in prev_keep:
        mark_success(history, s, speed_checked=False)
        s['skip_speed'] = True
        pool.append(s)
    for s in tested:
        mark_success(history, s, speed_checked=True)
        if s['speed_mbps'] >= SPEED_HARD_LIMIT:
            s['skip_speed'] = True
            pool.append(s)
    grace_failed = 0
    for s in failed_prev:
        if mark_failure(history, s) and s.get('speed_mbps', 0) >= SPEED_HARD_LIMIT:
            s['grace'] = True
            s['skip_speed'] = True
            pool.append(s)
            grace_failed += 1
    for s in untested_prev:
        if s.get('speed_mbps', 0) >= SPEED_HARD_LIMIT:
            s['skip_speed'] = True
            pool.append(s)
    if grace_failed:
        logger.info(f"🕊 Старых, проваливших STAGE 1, оставлено в грейс-периоде: {grace_failed}")

    for s in pool:
        s['score'] = calculate_quality_score(s, history)

    seen = set()
    pool = [s for s in pool if not (node_id_of(s) in seen or seen.add(node_id_of(s)))]
    pool.sort(key=lambda x: (0 if x.get('from_prev') else 1, x.get('real_delay', 9999), -x.get('score', 0)))
    selection = pool[:MAX_SUBSCRIPTION_SERVERS]
    n_old = sum(1 for s in selection if s.get('from_prev'))
    logger.info(f"🗂 В пуле {len(pool)} узлов, в подписку идёт {len(selection)}: старых {n_old}, новых {len(selection) - n_old}.")

    # ── STAGE 2 ──
    to_verify = [s for s in selection if not s.get('grace')]
    passthrough = [s for s in selection if s.get('grace')]
    logger.info(f"\n⚡ ЭТАП 2: индивидуальная проверка {len(to_verify)} узлов (грейс без проверки: {len(passthrough)}), "
                f"осталось бюджета {time_left():.0f} сек")
    t2 = time.time()
    verified = list(passthrough)
    dropped_new, grace2 = 0, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=STAGE2_WORKERS) as ex:
        fm = {ex.submit(measure_node_stats, s, check_speed=not s.get('skip_speed', False)): s for s in to_verify}
        done = 0
        for f in concurrent.futures.as_completed(fm):
            done += 1
            s = fm[f]
            try:
                s, ok = f.result()
            except Exception:
                ok = False
            if not ok:
                if s.get('from_prev') and mark_failure(history, s):
                    s['grace'] = True          # старый — грейс со старыми показателями
                    grace2 += 1
                else:
                    dropped_new += 1
                    continue
            verified.append(s)
            disp = COUNTRIES_RU.get(s['country'], s['country'])
            logger.info(f"   [{done}/{len(to_verify)}] {disp} -> {s.get('real_delay', 0)}ms | {s.get('speed_mbps', 0.0)} Mbps"
                        + (" (грейс)" if s.get('grace') else ""))
    logger.info(f"📊 ЭТАП 2: {time.time() - t2:.0f} сек | отсеяно {dropped_new}, в грейс {grace2}")

    # Итоговый порядок детерминирован (as_completed его перемешивал)
    verified.sort(key=lambda x: (0 if x.get('from_prev') else 1, x.get('real_delay', 9999), -x.get('score', 0)))

    # ── Предохранитель: подозрительно маленький результат — состояние НЕ трогаем ──
    # Иначе один сбойный прогон (сеть, Xray, проверка протоколов) перезаписал бы
    # subscription и историю, и следующий прогон стартовал бы с пустого состояния.
    if prev_count and len(verified) < max(1, prev_count * MIN_RESULT_RATIO_PCT // 100):
        logger.error(f"❌ Получено {len(verified)} узлов против {prev_count} в прошлой подписке "
                     f"(< {MIN_RESULT_RATIO_PCT}%) — похоже на сбой. subscription и история НЕ перезаписаны.")
        write_meta(len(verified), prev_count, 0)
        sys.exit(2)

    # ── Формирование подписки ──
    result_links, json_stats = [], {"servers": []}
    for s in verified:
        country = COUNTRIES_RU.get(s['country'], f"🏳️ {s['country']}")
        star = "🌟" if history.get(node_id_of(s), {}).get("streak", 0) >= 3 else ""
        # Формат имени: [Ping:<мс>ms|Speed:<мб/с>Mbps] — парсится при следующем запуске
        name = f"{star}{get_speed_badge(s['speed_mbps'])}{country} [Ping:{s.get('real_delay', 0)}ms|Speed:{s.get('speed_mbps', 0.0)}Mbps]"
        result_links.append(f"{s['original'].split('#')[0]}#{quote(name)}")
        json_stats["servers"].append({
            "name": name, "ip": s['ip'], "ping": s.get('real_delay', 0), "speed_mbps": s.get('speed_mbps', 0.0),
            "score": s.get('score', 0), "country": s.get('country', 'XX'),
            "protocol": f"{s['protocol']} {s.get('security', '')}".strip(),
        })

    sealed = seal("\n".join(result_links), SUB_KEY)
    # Самопроверка: файл обязан расшифровываться тем же ключом
    assert unseal(sealed, SUB_KEY).count("\n") + 1 == max(1, len(result_links))

    publish_subscription(sealed)
    if os.getenv("V1A_WRITE_STATS", "0") == "1":
        with open(JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump(json_stats, f, indent=2, ensure_ascii=False)

    # История — ПОСЛЕ подписки, чтобы при обрыве не разойтись
    pruned = prune_history(history)
    save_history(history)
    write_meta(len(result_links), prev_count, len(sealed))

    logger.info(f"💾 Готово: {len(result_links)} узлов, файл {len(sealed) // 1024} КБ. История: {len(history)} записей "
                f"(удалено устаревших: {pruned}). Всего прогон: {time.time() - RUN_START:.0f} сек")


if __name__ == "__main__":
    main()
