#!/usr/bin/env python3

import os, sys, json, secrets, hashlib, logging, base64, time, threading, mimetypes, re
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from io import BytesIO
import hmac as std_hmac

from flask import Flask, request, jsonify, render_template_string, Response
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import serialization
import webview

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("EveryCrypt")
if not PIL_AVAILABLE:
    logger.warning("Pillow не установлен. pip install Pillow")

BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = BASE_DIR / "cached" / "v1"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

CERT_DIR = BASE_DIR / "cert"
CERT_DIR.mkdir(parents=True, exist_ok=True)
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"
CERT_INSTALLED_FLAG = CERT_DIR / ".installed"
USE_SSL = False

PEPPER_DIR = Path.home() / ".EveryCrypt"
PEPPER_FILE = PEPPER_DIR / "global_pepper.key"
PEPPER_DIR.mkdir(parents=True, exist_ok=True)

SETTINGS_FILE = BASE_DIR / "settings.cfg"
SETTINGS_KEY_FILE = BASE_DIR / "settings.key"

ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 262144
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
MAX_FILE_SIZE = 1024 * 1024 * 1024
MAX_FILENAME_LENGTH = 255
SESSION_TTL = 30 * 60
DEFAULT_INACTIVITY_LOCK = 25  # По умолчанию 25 секунд
PREVIEW_TOKEN_TTL = 60
THUMBNAIL_TOKEN_TTL = 300
THUMBNAIL_SIZE = (256, 256)
FLASK_PORT = 58921

APP_SECRET_TOKEN = secrets.token_hex(32)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE + 1024 * 1024

# ─── Шифрованные настройки ───────────────────────

def load_settings_key():
    if SETTINGS_KEY_FILE.exists():
        return SETTINGS_KEY_FILE.read_bytes()
    key = secrets.token_bytes(32)
    SETTINGS_KEY_FILE.write_bytes(key)
    return key

def get_settings_key():
    return load_settings_key()

def decrypt_settings(data: bytes) -> dict:
    try:
        key = get_settings_key()
        dec = decrypt_data(data, key)
        return json.loads(dec.decode('utf-8'))
    except:
        return {}

def encrypt_settings(settings: dict) -> bytes:
    key = get_settings_key()
    return encrypt_data(json.dumps(settings, ensure_ascii=False).encode('utf-8'), key)

def load_theme_from_file() -> str:
    try:
        if SETTINGS_FILE.exists():
            data = SETTINGS_FILE.read_bytes()
            settings = decrypt_settings(data)
            return settings.get('theme', 'light')
    except Exception as e:
        logger.warning(f"Не удалось загрузить тему: {e}")
    return 'light'

def save_theme_to_file(theme: str):
    try:
        settings = {}
        if SETTINGS_FILE.exists():
            try:
                settings = decrypt_settings(SETTINGS_FILE.read_bytes())
            except:
                settings = {}
        settings['theme'] = theme
        SETTINGS_FILE.write_bytes(encrypt_settings(settings))
    except Exception as e:
        logger.warning(f"Не удалось сохранить тему: {e}")

def load_blocking_mode() -> bool:
    try:
        if SETTINGS_FILE.exists():
            settings = decrypt_settings(SETTINGS_FILE.read_bytes())
            return settings.get('block_browsers', True)
    except:
        pass
    return True

def save_blocking_mode(enabled: bool):
    try:
        settings = {}
        if SETTINGS_FILE.exists():
            try:
                settings = decrypt_settings(SETTINGS_FILE.read_bytes())
            except:
                settings = {}
        settings['block_browsers'] = enabled
        SETTINGS_FILE.write_bytes(encrypt_settings(settings))
    except Exception as e:
        logger.warning(f"Не удалось сохранить режим блокировки: {e}")

def load_lock_timeout() -> int:
    """Загружает время блокировки из настроек (по умолчанию 25 секунд)"""
    try:
        if SETTINGS_FILE.exists():
            settings = decrypt_settings(SETTINGS_FILE.read_bytes())
            return settings.get('lock_timeout', DEFAULT_INACTIVITY_LOCK)
    except:
        pass
    return DEFAULT_INACTIVITY_LOCK

def save_lock_timeout(seconds: int):
    """Сохраняет время блокировки в настройки"""
    try:
        settings = {}
        if SETTINGS_FILE.exists():
            try:
                settings = decrypt_settings(SETTINGS_FILE.read_bytes())
            except:
                settings = {}
        settings['lock_timeout'] = seconds
        SETTINGS_FILE.write_bytes(encrypt_settings(settings))
    except Exception as e:
        logger.warning(f"Не удалось сохранить время блокировки: {e}")

# ─── Защита от MITM ──────────────────────────────

@app.before_request
def check_request_source():
    if request.path.startswith('/static/'):
        return None
    
    block_browsers = load_blocking_mode()
    
    if not block_browsers:
        return None
    
    url_token = request.args.get('token', '')
    cookie_token = request.cookies.get('ec_token', '')
    header_token = request.headers.get('X-EveryCrypt-Token', '')
    
    valid_tokens = [APP_SECRET_TOKEN]
    
    if url_token in valid_tokens or cookie_token in valid_tokens or header_token in valid_tokens:
        return None
    
    logger.warning(f"Warning: {request.path} | UA: {request.headers.get('User-Agent', 'N/A')[:50]}")
    
    return render_template_string('''<title>Forbidden 403</title>403'''), 403

@app.after_request
def set_auth_cookie(response):
    if request.args.get('token') == APP_SECRET_TOKEN:
        response.set_cookie('ec_token', APP_SECRET_TOKEN, httponly=True, samesite='Strict', max_age=86400)
    return response

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Referrer-Policy'] = 'no-referrer'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'"
    return response

# ─── Криптография ────────────────────────────────

def secure_compare(a: bytes, b: bytes) -> bool:
    return std_hmac.compare_digest(a, b)

def derive_keys(password: str, pepper_bytes: bytes, salt: bytes) -> dict:
    combined = password.encode('utf-8') + pepper_bytes
    ikm = hash_secret_raw(secret=combined, salt=salt, time_cost=ARGON2_TIME_COST,
                          memory_cost=ARGON2_MEMORY_COST, parallelism=ARGON2_PARALLELISM,
                          hash_len=ARGON2_HASH_LEN, type=Type.ID)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32*3+16, salt=None, info=b"EveryCrypt_v1_keys")
    km = hkdf.derive(ikm)
    keys = {'enc_key': km[0:32], 'map_key': km[32:64], 'hdr_key': km[64:96], 'integ_key': km[96:112]}
    cs = secrets.token_bytes(16)
    keys['check_salt'] = cs
    keys['key_hash'] = hash_secret_raw(secret=ikm, salt=cs, time_cost=1, memory_cost=8*1024,
                                       parallelism=1, hash_len=32, type=Type.ID)
    return keys

def encrypt_data(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, data, None)

def decrypt_data(encrypted: bytes, key: bytes) -> bytes:
    if len(encrypted) < 28: raise ValueError("Данные повреждены")
    return ChaCha20Poly1305(key).decrypt(encrypted[:12], encrypted[12:], None)

def load_or_create_pepper() -> bytes:
    if PEPPER_FILE.exists():
        with open(PEPPER_FILE, 'rb') as f: pepper = f.read()
        if len(pepper) >= 32: return pepper[:32]
    pepper = secrets.token_bytes(32)
    with open(PEPPER_FILE, 'wb') as f: f.write(pepper)
    if os.name == 'nt':
        try:
            import subprocess; subprocess.run(['cipher', '/e', str(PEPPER_FILE)], check=False)
        except: pass
    else: PEPPER_FILE.chmod(0o600)
    return pepper

def normalize_filename(name: str) -> str:
    if not name: raise ValueError("Пустое имя файла")
    name = ''.join(ch for ch in name if ord(ch) >= 32 and ch != '\x7f')
    name = name.strip()
    if name in ('.', '..'): raise ValueError("Запрещённое имя файла")
    if len(name) > MAX_FILENAME_LENGTH: name = name[:MAX_FILENAME_LENGTH]
    name = re.sub(r'[<>:"/\\|?*]' if os.name == 'nt' else r'[/]', '_', name)
    if not name: raise ValueError("Некорректное имя файла")
    return name

def is_image_ext(filename: str) -> bool:
    if '.' not in filename: return False
    return filename.rsplit('.', 1)[-1].lower() in ('jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp')

def generate_thumbnail(image_data: bytes) -> Optional[bytes]:
    if not PIL_AVAILABLE: return None
    try:
        img = Image.open(BytesIO(image_data))
        if img.mode == 'RGBA':
            bg = Image.new('RGB', img.size, (255, 255, 255)); bg.paste(img, mask=img.split()[3]); img = bg
        elif img.mode == 'P':
            img = img.convert('RGBA'); bg = Image.new('RGB', img.size, (255, 255, 255)); bg.paste(img, mask=img.split()[3]); img = bg
        elif img.mode not in ('RGB', 'L'): img = img.convert('RGB')
        img.thumbnail(THUMBNAIL_SIZE, Image.Resampling.LANCZOS)
        out = BytesIO(); img.save(out, format='JPEG', quality=70); out.seek(0)
        return out.getvalue()
    except Exception as e:
        logger.warning(f"Thumbnail failed: {e}")
        return None

def vault_path(vault_id: str) -> Path: return CACHE_DIR / vault_id

def load_header(vp: Path) -> dict:
    content = (vp / 'header.crypt').read_bytes()
    sep = b'\n--SIG--\n'
    if sep not in content: raise ValueError("Неверный формат header")
    raw, sig = content.split(sep, 1)
    h = json.loads(raw.decode('utf-8'))
    h['_raw'], h['_sig'] = raw, sig
    return h

def save_header(vp: Path, header: dict, hdr_key: bytes):
    raw = json.dumps(header, sort_keys=True, ensure_ascii=False).encode('utf-8')
    h = HMAC(hdr_key, hashes.SHA256()); h.update(raw)
    (vp / 'header.crypt').write_bytes(raw + b'\n--SIG--\n' + h.finalize())

def load_mapping(vp: Path, map_key: bytes) -> dict:
    mf = vp / 'mapping.crypt'
    if not mf.exists(): return {'/': {'files': {}, 'dirs': []}}
    encrypted = mf.read_bytes()
    if not encrypted: return {'/': {'files': {}, 'dirs': []}}
    m = json.loads(decrypt_data(encrypted, map_key).decode('utf-8'))
    if '/' not in m: m['/'] = {'files': {}, 'dirs': []}
    return m

def save_mapping(vp: Path, mapping: dict, map_key: bytes):
    (vp / 'mapping.crypt').write_bytes(encrypt_data(json.dumps(mapping, sort_keys=True, ensure_ascii=False).encode('utf-8'), map_key))

def find_real_path(mapping: dict, display_path: str, enc_key: bytes) -> str:
    if display_path == '/': return '/'
    if '..' in display_path: return '/'
    parts = display_path.strip('/').split('/')
    if any(p in ('.', '..') or not p for p in parts): return '/'
    current = '/'
    for part in parts:
        if current not in mapping: return '/'
        entry = mapping[current]
        found = False
        for enc_dir in entry.get('dirs', []):
            try:
                dec_dir = decrypt_data(base64.b64decode(enc_dir), enc_key).decode()
                if dec_dir == part:
                    current = current.rstrip('/') + '/' + enc_dir
                    found = True
                    break
            except: pass
        if not found: return '/'
    return current

def create_vault(name: str, password: str, pepper: bytes, encrypt_name: bool = False) -> dict:
    salt = secrets.token_bytes(16)
    keys = derive_keys(password, pepper, salt)
    vh = hashlib.sha256(name.encode()).hexdigest()[:16]
    vp = vault_path(vh); vp.mkdir(parents=True, exist_ok=True)
    name_stored = base64.b64encode(encrypt_data(name.encode(), keys['enc_key'])).decode('ascii')
    name_hint = f'Хранилище {vh[:8]}' if encrypt_name else name
    header = {
        'version': 6, 'name_enc': name_stored, 'encrypt_name': encrypt_name,
        'name_hint': name_hint, 'salt': base64.b64encode(salt).decode('ascii'),
        'check_salt': base64.b64encode(keys['check_salt']).decode('ascii'),
        'key_hash': base64.b64encode(keys['key_hash']).decode('ascii'),
        'time_cost': ARGON2_TIME_COST, 'memory_cost': ARGON2_MEMORY_COST,
        'created_at': datetime.now().isoformat()
    }
    save_header(vp, header, keys['hdr_key'])
    save_mapping(vp, {'/': {'files': {}, 'dirs': []}}, keys['map_key'])
    return {'id': vh, 'name': name, 'name_hint': name_hint, 'created_at': header['created_at']}

def open_vault(vault_id: str, password: str, pepper: bytes) -> Optional[dict]:
    vp = vault_path(vault_id)
    if not vp.exists(): return None
    try: header = load_header(vp)
    except: return None
    salt = base64.b64decode(header['salt'])
    keys = derive_keys(password, pepper, salt)
    h = HMAC(keys['hdr_key'], hashes.SHA256()); h.update(header['_raw'])
    if not secure_compare(h.finalize(), header['_sig']): return None
    check_salt = base64.b64decode(header['check_salt'])
    stored_hash = base64.b64decode(header['key_hash'])
    ikm = hash_secret_raw(secret=password.encode() + pepper, salt=salt, time_cost=ARGON2_TIME_COST,
                          memory_cost=ARGON2_MEMORY_COST, parallelism=ARGON2_PARALLELISM,
                          hash_len=ARGON2_HASH_LEN, type=Type.ID)
    computed = hash_secret_raw(secret=ikm, salt=check_salt, time_cost=1, memory_cost=8*1024,
                               parallelism=1, hash_len=32, type=Type.ID)
    if not secure_compare(computed, stored_hash): return None
    name = decrypt_data(base64.b64decode(header['name_enc']), keys['enc_key']).decode()
    return {'id': vault_id, 'name': name, 'keys': keys, 'path': vp, 'last_active': time.time()}

active_sessions: Dict[str, Dict[str, Any]] = {}
preview_tokens: Dict[str, Dict[str, Any]] = {}
thumbnail_tokens: Dict[str, Dict[str, Any]] = {}
login_attempts: Dict[str, Dict[str, Any]] = {}

def cleanup_sessions():
    now = time.time()
    for t in list(active_sessions.keys()):
        if now - active_sessions[t].get('last_active', 0) > SESSION_TTL:
            v = active_sessions.pop(t)
            if 'keys' in v:
                for k in ('enc_key', 'map_key', 'hdr_key', 'integ_key'):
                    if k in v['keys'] and isinstance(v['keys'][k], (bytes, bytearray)):
                        v['keys'][k] = b'\x00' * len(v['keys'][k])
                v['keys'].clear()
            v.clear()

def cleanup_tokens():
    now = time.time()
    for d, ttl in [(preview_tokens, PREVIEW_TOKEN_TTL), (thumbnail_tokens, THUMBNAIL_TOKEN_TTL)]:
        for t in list(d.keys()):
            if now - d[t].get('created', 0) > ttl: d.pop(t, None)

def format_delay(seconds: int) -> str:
    if seconds < 60: return f'{seconds} сек.'
    elif seconds < 3600: return f'{seconds // 60} мин.'
    else: return f'{seconds // 3600} час.'

# ─── HTML ─────────────────────────────────────────
HTML = r'''<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EveryCrypt</title>
    <link href="/static/css/roboto.css" rel="stylesheet">
    <link href="/static/css/rounded.css" rel="stylesheet">
    <style>
    .preview-image-btn{width:48px;height:48px;border-radius:50%;background:rgba(0,0,0,0.6);color:#fff;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background 0.2s}.preview-image-btn:hover{background:rgba(0,0,0,0.8)}.preview-image-btn .material-symbols-rounded{font-size:24px}
        :root{--md-primary:#1A73E8;--md-on-primary:#FFFFFF;--md-primary-container:#D3E3FD;--md-on-primary-container:#041E49;--md-secondary-container:#E8EAED;--md-on-secondary-container:#1F1F1F;--md-error:#D93025;--md-surface:#FFFFFF;--md-on-surface:#1F1F1F;--md-surface-variant:#F1F3F4;--md-on-surface-variant:#444746;--md-outline:#747775;--md-outline-variant:#C4C7C5;--md-surface-container:#F1F3F4;--md-surface-container-lowest:#FFFFFF;--md-surface-container-high:#E8EAED;--md-surface-container-highest:#E0E2E5;--md-shape-small:8px;--md-shape-medium:12px;--md-shape-large:16px;--md-shape-full:9999px;--md-elevation-1:0 1px 2px rgba(0,0,0,0.3),0 1px 3px 1px rgba(0,0,0,0.15);--md-elevation-2:0 1px 2px rgba(0,0,0,0.3),0 2px 6px 2px rgba(0,0,0,0.15);--md-elevation-3:0 4px 8px 3px rgba(0,0,0,0.15),0 1px 3px rgba(0,0,0,0.3)}
        .dark-theme{--md-primary:#8AB4F8;--md-on-primary:#062E6F;--md-primary-container:#0842A0;--md-on-primary-container:#D3E3FD;--md-secondary-container:#3C4043;--md-on-secondary-container:#E8EAED;--md-error:#F28B82;--md-surface:#1F1F1F;--md-on-surface:#E8EAED;--md-surface-variant:#303134;--md-on-surface-variant:#9AA0A6;--md-outline:#5F6368;--md-outline-variant:#3C4043;--md-surface-container:#303134;--md-surface-container-lowest:#1F1F1F;--md-surface-container-high:#3C4043;--md-surface-container-highest:#4A4D52;--md-elevation-1:0 1px 2px rgba(0,0,0,0.6),0 1px 3px 1px rgba(0,0,0,0.3);--md-elevation-2:0 1px 2px rgba(0,0,0,0.6),0 2px 6px 2px rgba(0,0,0,0.3);--md-elevation-3:0 4px 8px 3px rgba(0,0,0,0.3),0 1px 3px rgba(0,0,0,0.6)}
        *{margin:0;padding:0;box-sizing:border-box}body{font-family:'Roboto',sans-serif;background:var(--md-surface);color:var(--md-on-surface);min-height:100vh;user-select:none}.app-bar{background:var(--md-surface-container);padding:0 16px;display:flex;align-items:center;height:64px;border-bottom:1px solid var(--md-outline-variant);position:sticky;top:0;z-index:100}.app-bar-leading{display:flex;align-items:center;margin-right:8px}.app-bar-headline{font-size:18px;font-weight:400;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.app-bar-actions{display:flex;gap:4px}.content{max-width:1200px;margin:0 auto;padding:24px;padding-bottom:100px}.card{background:var(--md-surface-container-lowest);border-radius:var(--md-shape-medium);padding:24px;margin-bottom:16px;box-shadow:var(--md-elevation-1);border:1px solid var(--md-outline-variant)}.card-title{font-size:18px;font-weight:400;margin-bottom:16px}.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 24px;border:none;border-radius:var(--md-shape-full);font-family:'Roboto',sans-serif;font-size:14px;font-weight:500;cursor:pointer;height:40px;letter-spacing:0.1px}.btn-filled{background:var(--md-primary);color:var(--md-on-primary)}.btn-tonal{background:var(--md-secondary-container);color:var(--md-on-secondary-container)}.btn-outlined{background:transparent;color:var(--md-primary);border:1px solid var(--md-outline)}.btn-icon{width:40px;height:40px;padding:0;justify-content:center;background:transparent;border-radius:50%;color:var(--md-on-surface-variant);border:none;outline:none;display:inline-flex;align-items:center;cursor:pointer}.btn-icon:hover{background:var(--md-surface-container-highest)}.btn .material-symbols-rounded{font-size:18px}.input-field{margin-bottom:24px}.input-label{display:block;font-size:12px;font-weight:400;color:var(--md-primary);margin-bottom:4px;padding-left:4px}.input-text{width:100%;padding:8px 0;border:none;border-bottom:1px solid var(--md-outline);font-size:16px;background:transparent;color:var(--md-on-surface);outline:none;border-radius:4px 4px 0 0}.input-text:focus{border-bottom:2px solid var(--md-primary);padding-bottom:7px}.input-helper{font-size:12px;color:var(--md-on-surface-variant);margin-top:4px;padding-left:4px}.checkbox-field{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding:8px 4px}.file-list{list-style:none}.file-item{display:flex;align-items:center;padding:8px 16px;border-radius:var(--md-shape-small);cursor:pointer;gap:16px;min-height:52px}.file-item:hover{background:var(--md-surface-container-highest)}.file-item-leading{color:var(--md-on-surface-variant);flex-shrink:0;font-size:24px;width:40px;height:40px;display:flex;align-items:center;justify-content:center;overflow:hidden;border-radius:var(--md-shape-small)}.file-item-leading img{width:100%;height:100%;object-fit:cover;border-radius:var(--md-shape-small)}.file-item-content{flex:1;min-width:0}.file-item-name{font-size:16px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.file-item-meta{font-size:14px;color:var(--md-on-surface-variant)}.file-item-trailing{display:flex;gap:4px;flex-shrink:0}.file-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px}.file-grid .file-card{text-align:center;padding:12px 8px;border-radius:var(--md-shape-medium);cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:8px}.file-grid .file-card:hover{background:var(--md-surface-container-highest)}.file-grid .file-card .file-icon{width:80px;height:80px;border-radius:var(--md-shape-medium);overflow:hidden;display:flex;align-items:center;justify-content:center;background:var(--md-surface-container)}.file-grid .file-card .file-icon img{width:100%;height:100%;object-fit:cover}.file-grid .file-card .file-icon .material-symbols-rounded{font-size:48px;color:var(--md-primary)}.file-grid .file-card .file-name{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}.file-grid-large{grid-template-columns:repeat(auto-fill,minmax(180px,1fr))}.file-grid-large .file-card .file-icon{width:120px;height:120px}.file-grid-large .file-card .file-icon .material-symbols-rounded{font-size:64px}.file-grid-small{grid-template-columns:repeat(auto-fill,minmax(90px,1fr))}.file-grid-small .file-card .file-icon{width:56px;height:56px}.file-grid-small .file-card .file-icon .material-symbols-rounded{font-size:36px}.file-list-container{position:relative;min-height:60vh}.empty-state{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;color:var(--md-on-surface-variant);padding:48px 24px;width:100%}.empty-state .material-symbols-rounded{font-size:64px;margin-bottom:16px;color:var(--md-outline-variant)}.empty-state-text{font-size:16px;margin-bottom:8px}.breadcrumbs{display:flex;align-items:center;gap:4px;padding:4px 0;margin-bottom:8px;overflow-x:auto;flex-wrap:wrap}.breadcrumb{font-size:14px;color:var(--md-primary);cursor:pointer;white-space:nowrap;padding:4px 8px;border-radius:var(--md-shape-small);display:inline-flex;align-items:center}.breadcrumb:hover{background:var(--md-primary-container)}.breadcrumb-active{color:var(--md-on-surface);cursor:default}.breadcrumb-sep{color:var(--md-on-surface-variant);margin:0 2px;font-size:18px}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}.dialog-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:1000;backdrop-filter:blur(4px)}.dialog{background:var(--md-surface-container-high);border-radius:28px;padding:24px;width:560px;max-width:90vw;box-shadow:var(--md-elevation-3);animation:dialogIn 0.3s ease-out}@keyframes dialogIn{from{opacity:0;transform:scale(0.95)}to{opacity:1;transform:scale(1)}}.dialog-title{font-size:20px;font-weight:400;margin-bottom:16px}.dialog-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:24px}.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#2E2E2E;color:#FFFFFF;padding:14px 16px;border-radius:4px;font-size:14px;box-shadow:var(--md-elevation-3);z-index:2000;animation:toastIn 0.3s ease-out;display:flex;align-items:center;gap:12px}@keyframes toastIn{from{opacity:0;transform:translateX(-50%) translateY(20px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}.preview-image{max-width:80vw;max-height:80vh;border-radius:var(--md-shape-medium);box-shadow:var(--md-elevation-3)}.divider{height:1px;background:var(--md-outline-variant);margin:8px 0}.view-toggle{display:flex;gap:4px;background:var(--md-surface-container-highest);border-radius:var(--md-shape-full);padding:4px}.view-toggle .btn-icon{border-radius:var(--md-shape-full)}.view-toggle .btn-icon.active{background:var(--md-surface-container-lowest);box-shadow:var(--md-elevation-1)}.lock-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.85);display:flex;align-items:center;justify-content:center;z-index:3000;backdrop-filter:blur(10px)}.lock-dialog{background:var(--md-surface-container-high);border-radius:28px;padding:32px;text-align:center;box-shadow:var(--md-elevation-3);min-width:360px}.lock-icon{font-size:48px;color:var(--md-primary);margin-bottom:16px}.fab{position:fixed;bottom:24px;right:24px;width:56px;height:56px;border-radius:16px;background:var(--md-primary-container);color:var(--md-on-primary-container);border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:var(--md-elevation-3);z-index:50}.fab .material-symbols-rounded{font-size:24px}.switch-container{display:flex;align-items:center;justify-content:space-between;padding:12px 0}.switch{position:relative;display:inline-block;width:52px;height:32px}.switch input{opacity:0;width:0;height:0}.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:var(--md-outline);transition:0.3s;border-radius:32px}.slider:before{position:absolute;content:"";height:24px;width:24px;left:4px;bottom:4px;background:var(--md-surface);transition:0.3s;border-radius:50%}input:checked+.slider{background:var(--md-primary)}input:checked+.slider:before{transform:translateX(20px)}select.sort-select{padding:8px 16px;border:1px solid var(--md-outline);border-radius:var(--md-shape-full);background:var(--md-surface);color:var(--md-on-surface);font-family:Roboto;font-size:14px;cursor:pointer;height:40px}.context-menu{position:fixed;background:var(--md-surface-container-high);border-radius:var(--md-shape-medium);box-shadow:var(--md-elevation-3);z-index:1500;min-width:180px;padding:8px 0;display:none}.context-menu-item{padding:8px 16px;cursor:pointer;display:flex;align-items:center;gap:12px;font-size:14px;color:var(--md-on-surface)}.context-menu-item:hover{background:var(--md-surface-container-highest)}.context-menu-item .material-symbols-rounded{font-size:18px;color:var(--md-on-surface-variant)}@media(max-width:600px){.content{padding:16px}.dialog{min-width:auto;width:100%;margin:16px}.grid{grid-template-columns:1fr}}
    </style>
</head>
<body>
<div id="app"></div>
<div id="lock-screen"></div>
<div class="context-menu" id="context-menu"></div>
<script>
var STATE={view:'vaults',currentVault:null,currentPath:'/',sessionToken:null,viewMode:'list',inactivityTimer:null,locked:false,theme:'light',files:[],dirs:[],contextFile:null,contextIsDir:false,lockTimeout:25};
var thumbnailUrls={};
var APP_TOKEN='{APP_TOKEN}';

function loadThemeFromServer(){fetch('/api/get_theme').then(r=>r.json()).then(d=>{if(d.success){STATE.theme=d.theme;if(STATE.theme==='dark'){document.body.classList.add('dark-theme');}else{document.body.classList.remove('dark-theme');}}}).catch(()=>{});}
function saveThemeToServer(theme){fetch('/api/save_theme',{method:'POST',headers:{'Content-Type':'application/json','X-EveryCrypt-Token':APP_TOKEN},body:JSON.stringify({theme:theme})}).catch(()=>{});}
loadThemeFromServer();

function escapeHtml(text){var d=document.createElement('div');d.appendChild(document.createTextNode(text));return d.innerHTML;}
function escapeJsString(s){return s.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"').replace(/\//g,'\\/').replace(/\n/g,'\\n').replace(/\r/g,'\\r').replace(/\t/g,'\\t').replace(/[\b\f]/g,'').replace(/`/g,'\\`').replace(/\$/g,'\\$');}
function formatSize(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(1)+' GB';}
function formatDate(ts){if(!ts)return'';var d=new Date(ts*1000);return d.toLocaleString('ru-RU');}
function showToast(m,i){var t=document.createElement('div');t.className='toast';t.innerHTML=(i?'<span class="material-symbols-rounded">'+i+'</span>':'')+m;document.body.appendChild(t);setTimeout(function(){t.style.opacity='0';t.style.transition='opacity 0.3s';setTimeout(function(){t.remove();},300);},3000);}
function closeDialog(){var c=document.getElementById('dialog-container');if(c)c.innerHTML='';}
function resetInactivityTimer(){if(STATE.locked)return;var d=document.getElementById('dialog-container');if(d&&d.innerHTML.replace(/\s/g,'')!=='')return;clearTimeout(STATE.inactivityTimer);var t=STATE.lockTimeout||25;if(t>0)STATE.inactivityTimer=setTimeout(lockVault,t*1000);}
function lockVault(){if(!STATE.sessionToken||STATE.view!=='browser')return;var d=document.getElementById('dialog-container');if(d&&d.innerHTML.replace(/\s/g,'')!=='')return;STATE.locked=true;document.getElementById('lock-screen').innerHTML='<div class="lock-overlay"><div class="lock-dialog"><span class="material-symbols-rounded lock-icon">lock</span><div style="font-size:20px;margin-bottom:8px;">Хранилище заблокировано</div><div style="color:var(--md-on-surface-variant);margin-bottom:24px;">Неактивность</div><form onsubmit="unlockVault(event);return false"><div class="input-field"><label class="input-label">Пароль</label><input class="input-text" type="password" id="unlock-password" placeholder="Введите пароль" required autofocus></div><div class="dialog-actions"><button type="submit" class="btn btn-filled"><span class="material-symbols-rounded" style="font-size:18px;">lock_open</span>Разблокировать</button></div></form></div></div>';clearTimeout(STATE.inactivityTimer);setTimeout(function(){var el=document.getElementById('unlock-password');if(el)el.focus();},100);}
function unlockVault(e){
    if(e)e.preventDefault();
    var btn=document.querySelector('#lock-screen .btn-filled');
    if(btn&&btn.disabled)return; // Кнопка заблокирована
    
    var pw=document.getElementById('unlock-password').value;
    if(!pw)return;
    
    // Блокируем кнопку на время запроса
    if(btn){btn.disabled=true;btn.textContent='...';}
    
    api('open_vault',{vault_id:STATE.currentVault.id,password:pw},function(r){
        if(r.success){
            STATE.locked=false;
            STATE.sessionToken=r.session;
            document.getElementById('lock-screen').innerHTML='';
            resetInactivityTimer();
            showToast('Разблокировано','lock_open');
        }else{
            showToast(r.error||'Неверный пароль','error');
            var el=document.getElementById('unlock-password');
            if(el){el.value='';el.focus();}
            
            // Извлекаем секунды из сообщения об ошибке
            var msg=r.error||'';
            var match=msg.match(/(\d+)\s*сек/);
            if(match){
                var seconds=parseInt(match[1]);
                lockButton(document.querySelector('#lock-screen .btn-filled'),seconds);
            }else{
                if(btn){btn.disabled=false;btn.textContent='Разблокировать';}
            }
        }
    });
}
function api(method,data,callback){var x=new XMLHttpRequest();x.open('POST','/api/'+method,true);x.setRequestHeader('Content-Type','application/json');x.setRequestHeader('X-EveryCrypt-Token',APP_TOKEN);x.onload=function(){try{callback(JSON.parse(x.responseText));}catch(e){callback({success:false,error:'Ошибка ответа'});}};x.onerror=function(){callback({success:false,error:'Нет соединения'});};x.send(JSON.stringify(data||{}));}
function uploadFile(file,callback){var fd=new FormData();fd.append('file',file);fd.append('vault_id',STATE.currentVault.id);fd.append('session',STATE.sessionToken);fd.append('path',STATE.currentPath);var x=new XMLHttpRequest();x.open('POST','/api/upload_file',true);x.setRequestHeader('X-EveryCrypt-Token',APP_TOKEN);x.onload=function(){try{callback(JSON.parse(x.responseText));}catch(e){callback({success:false});}};x.onerror=function(){callback({success:false});};x.send(fd);}
function isImageFile(name){var ext=name.split('.').pop().toLowerCase();return['jpg','jpeg','png','gif','webp','bmp'].indexOf(ext)!==-1;}
function isTextFile(name){var ext=name.split('.').pop().toLowerCase();return['txt','md','log','csv','json','xml','html','css','js','py','sh','bat','ini','cfg','yaml','yml'].indexOf(ext)!==-1;}
function isExeFile(name){var ext=name.split('.').pop().toLowerCase();return['exe','msi','bat','cmd','sh','app','dmg','pkg'].indexOf(ext)!==-1;}
function isAudioFile(name){var ext=name.split('.').pop().toLowerCase();return['mp3','wav','ogg','flac','aac','m4a','wma'].indexOf(ext)!==-1;}
function isVideoFile(name){var ext=name.split('.').pop().toLowerCase();return['mp4','webm','avi','mkv','mov','wmv','flv'].indexOf(ext)!==-1;}

var currentSort='name_asc';
function sortFiles(method){currentSort=method;var files=STATE.files,dirs=STATE.dirs;dirs.sort(function(a,b){return method.indexOf('name')!==-1?(method==='name_asc'?a.localeCompare(b):b.localeCompare(a)):0;});files.sort(function(a,b){if(method==='name_asc') return a.name.localeCompare(b.name);if(method==='name_desc') return b.name.localeCompare(a.name);if(method==='size_asc') return a.size-b.size;if(method==='size_desc') return b.size-a.size;if(method==='date_asc') return (a.mtime||0)-(b.mtime||0);if(method==='date_desc') return (b.mtime||0)-(a.mtime||0);if(method.indexOf('type')!==-1){var ea=a.name.split('.').pop().toLowerCase();var eb=b.name.split('.').pop().toLowerCase();return method==='type_asc'?ea.localeCompare(eb):eb.localeCompare(ea);}return 0;});STATE.files=files;STATE.dirs=dirs;renderFileList();}

function handleFileDoubleClick(filename){resetInactivityTimer();if(isExeFile(filename)){showExeWarning(filename);return;}if(isImageFile(filename)){previewImage(filename);return;}if(isTextFile(filename)){previewText(filename);return;}if(isAudioFile(filename)||isVideoFile(filename)){playMedia(filename);return;}downloadFile(filename);}

function showExeWarning(filename){var countdown=3;document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" onclick="if(event.target===this)closeDialog()"><div class="dialog" onclick="event.stopPropagation()"><div class="dialog-title">⚠ Внимание!</div><div style="font-size:16px;margin-bottom:16px;color:var(--md-error);">Файл <b>'+escapeHtml(filename)+'</b> является исполняемым и может быть опасен!</div><div style="font-size:14px;color:var(--md-on-surface-variant);margin-bottom:24px;">Файл будет сохранён во временную папку и открыт. Запускайте только если уверены в источнике.</div><div class="dialog-actions"><button class="btn btn-outlined" onclick="closeDialog()">Отмена</button><button class="btn btn-filled" id="exe-open-btn" disabled style="opacity:0.5">Открыть (3)</button></div></div></div>';var btn=document.getElementById('exe-open-btn');var timer=setInterval(function(){countdown--;if(countdown<=0){clearInterval(timer);btn.disabled=false;btn.style.opacity='1';btn.textContent='Открыть';btn.onclick=function(){closeDialog();openExeFile(filename);};}else{btn.textContent='Открыть ('+countdown+')';}},1000);}
function openExeFile(filename){if(window.pywebview&&window.pywebview.api){window.pywebview.api.open_exe_file(STATE.currentVault.id,STATE.sessionToken,STATE.currentPath,filename);}else{showToast('Открытие .exe недоступно в браузере','error');}}
function getThumbnailUrl(filename,callback){api('get_thumbnail_token',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath,filename:filename},function(resp){if(resp.success&&resp.token){callback('/api/thumbnail?token='+resp.token);}else{callback(null);}});}

function previewImage(filename){resetInactivityTimer();
    api('get_preview_token',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath,filename:filename},function(resp){
        if(resp.success&&resp.token){
            document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" style="background:rgba(0,0,0,0.85);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);z-index:2000;display:flex;align-items:center;justify-content:center;" onclick="closeDialog()"><button class="btn-icon" onclick="event.stopPropagation();closeDialog()" style="position:fixed;top:16px;left:16px;background:rgba(255,255,255,0.2);color:#fff;z-index:2001;width:48px;height:48px;" aria-label="Закрыть"><span class="material-symbols-rounded" style="font-size:28px;">close</span></button><button class="btn-icon" onclick="event.stopPropagation();fullscreenView(\''+resp.token+'\')" style="position:fixed;top:16px;right:16px;background:rgba(255,255,255,0.2);color:#fff;z-index:2001;width:48px;height:48px;" title="Полный экран" aria-label="Полный экран"><span class="material-symbols-rounded" style="font-size:28px;">fullscreen</span></button><img src="/api/preview_image?token='+resp.token+'" alt="" style="max-width:90vw;max-height:90vh;object-fit:contain;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.5);" id="preview-img" onwheel="zoomImage(event)" ondblclick="resetZoom(event)" onmousedown="startDrag(event)" onmousemove="dragImage(event)" onmouseup="endDrag()" onmouseleave="endDrag()" onclick="event.stopPropagation()"></div>';
            setTimeout(function(){var img=document.getElementById('preview-img');if(img){img._scale=1;img._tx=0;img._ty=0;img._dragging=false;}},100);
        }else{showToast('Предпросмотр недоступен','error');}});}

function fullscreenView(token){
    document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" style="background:#000;z-index:3000;display:flex;align-items:center;justify-content:center;overflow:hidden;" onclick="closeDialog()"><img src="/api/preview_image?token='+token+'" alt="" style="max-width:100vw;max-height:100vh;object-fit:contain;" id="fullscreen-img" onwheel="zoomImage(event)" ondblclick="resetZoom(event)" onmousedown="startDrag(event)" onmousemove="dragImage(event)" onmouseup="endDrag()" onmouseleave="endDrag()" onclick="event.stopPropagation()"></div>';
}

function zoomImage(e){
    e.preventDefault();
    var img=document.getElementById('preview-img')||document.getElementById('fullscreen-img');
    if(!img)return;
    if(!img._scale)img._scale=1;if(!img._tx)img._tx=0;if(!img._ty)img._ty=0;
    var rect=img.getBoundingClientRect();
    var cx=e.clientX-rect.left-rect.width/2;
    var cy=e.clientY-rect.top-rect.height/2;
    var ix=(cx-img._tx)/img._scale;
    var iy=(cy-img._ty)/img._scale;
    var delta=e.deltaY>0?-0.15:0.15;
    img._scale=Math.max(0.2,Math.min(5,img._scale+delta));
    img._tx=cx-ix*img._scale;
    img._ty=cy-iy*img._scale;
    img.style.transform='translate('+img._tx+'px,'+img._ty+'px) scale('+img._scale+')';
    img.style.cursor=img._scale>1?'grab':'default';
}

function startDrag(e){
    e.preventDefault();
    var img=document.getElementById('preview-img')||document.getElementById('fullscreen-img');
    if(!img||!img._scale||img._scale<=1)return;
    img._dragging=true;
    img._sx=e.clientX-(img._tx||0);
    img._sy=e.clientY-(img._ty||0);
}

function dragImage(e){
    var img=document.getElementById('preview-img')||document.getElementById('fullscreen-img');
    if(!img||!img._dragging)return;
    img._tx=e.clientX-img._sx;
    img._ty=e.clientY-img._sy;
    img.style.transform='translate('+img._tx+'px,'+img._ty+'px) scale('+(img._scale||1)+')';
}

function endDrag(){
    var img=document.getElementById('preview-img')||document.getElementById('fullscreen-img');
    if(img)img._dragging=false;
}

function resetZoom(e){
    if(e)e.stopPropagation();
    var img=document.getElementById('preview-img')||document.getElementById('fullscreen-img');
    if(img){img._scale=1;img._tx=0;img._ty=0;img.style.transform='translate(0,0) scale(1)';img.style.cursor='default';}
}

function previewText(filename){resetInactivityTimer();api('download_file',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath,filename:filename},function(resp){if(resp.success&&resp.data){try{var bin=atob(resp.data),bytes=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);var text=new TextDecoder('utf-8').decode(bytes);document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" onclick="closeDialog()"><div class="dialog" onclick="event.stopPropagation()" style="max-width:80vw;max-height:80vh;overflow:auto;user-select:text;"><div class="dialog-title">'+escapeHtml(filename)+'</div><pre style="white-space:pre-wrap;font-family:monospace;font-size:14px;color:var(--md-on-surface);user-select:text;" onmousedown="event.stopPropagation()">'+escapeHtml(text)+'</pre><div class="dialog-actions"><button class="btn btn-outlined" onclick="closeDialog()">Закрыть</button></div></div></div>';}catch(e){showToast('Не удалось прочитать файл','error');}}else showToast('Не удалось загрузить','error');});}

function playMedia(filename){resetInactivityTimer();
    api('get_preview_token',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath,filename:filename},function(resp){
        if(resp.success&&resp.token){
            var isVideo=isVideoFile(filename);
            document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" style="background:rgba(0,0,0,0.85);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);z-index:2000;display:flex;align-items:center;justify-content:center;" onclick="if(event.target===this)closeDialog()"><button class="btn-icon" onclick="event.stopPropagation();closeDialog()" style="position:fixed;top:16px;left:16px;background:rgba(255,255,255,0.2);color:#fff;z-index:2001;width:48px;height:48px;" aria-label="Закрыть"><span class="material-symbols-rounded" style="font-size:28px;">close</span></button><div style="width:75%;max-width:900px;" onclick="event.stopPropagation()"><'+(isVideo?'video':'audio')+' controls autoplay style="width:100%;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.5);" src="/api/preview_image?token='+resp.token+'"></'+(isVideo?'video':'audio')+'></div></div>';}
        else{showToast('Медиа недоступно','error');}});}

function navigateTo(path){resetInactivityTimer();path=path.replace(/\/+/g,'/').replace(/\/$/,'')||'/';STATE.currentPath=path;renderBreadcrumbs();loadFiles();hideContextMenu();}
function goBack(){resetInactivityTimer();if(STATE.currentPath=='/'){closeVault();return;}var parts=STATE.currentPath.split('/').filter(Boolean);parts.pop();STATE.currentPath='/'+parts.join('/')||'/';renderBreadcrumbs();loadFiles();hideContextMenu();}
function closeVault(){STATE.view='vaults';STATE.currentVault=null;STATE.currentPath='/';STATE.sessionToken=null;STATE.locked=false;clearTimeout(STATE.inactivityTimer);document.getElementById('lock-screen').innerHTML='';renderVaults();}
function refreshFiles(){resetInactivityTimer();loadFiles();}
function setViewMode(mode){STATE.viewMode=mode;renderFileList();}
function toggleTheme(){STATE.theme=STATE.theme==='dark'?'light':'dark';if(STATE.theme==='dark'){document.body.classList.add('dark-theme');}else{document.body.classList.remove('dark-theme');}saveThemeToServer(STATE.theme);}

function showCreateVaultDialog(){document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" onclick="if(event.target===this)closeDialog()"><div class="dialog" onclick="event.stopPropagation()"><div class="dialog-title">Новое хранилище</div><form onsubmit="createVaultForm(event);return false"><div class="input-field"><label class="input-label">Название</label><input class="input-text" type="text" id="vault-name-dialog" placeholder="Мои документы" required autofocus></div><div class="input-field"><label class="input-label">Пароль</label><input class="input-text" type="password" id="vault-password-dialog" placeholder="Минимум 8 символов" required minlength="8"></div><div class="checkbox-field"><input type="checkbox" id="vault-encrypt-name"><label for="vault-encrypt-name">Скрывать название хранилища</label></div><div class="dialog-actions"><button type="button" class="btn btn-outlined" onclick="closeDialog()">Отмена</button><button type="submit" class="btn btn-filled">Создать</button></div></form></div></div>';setTimeout(function(){var el=document.getElementById('vault-name-dialog');if(el)el.focus();},100);}
function createVaultForm(e){e.preventDefault();var n=document.getElementById('vault-name-dialog').value.trim(),p=document.getElementById('vault-password-dialog').value,enc=document.getElementById('vault-encrypt-name').checked;if(!n||!p){showToast('Заполните все поля','error');return;}if(p.length<8){showToast('Пароль минимум 8 символов','error');return;}api('create_vault',{name:n,password:p,encrypt_name:enc},function(r){if(r.success){closeDialog();loadVaults();showToast('Хранилище создано','check_circle');}else showToast(r.error||'Ошибка','error');});}

function openVaultDialog(id){document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" onclick="if(event.target===this)closeDialog()"><div class="dialog" onclick="event.stopPropagation()"><div class="dialog-title">Открыть хранилище</div><form onsubmit="openVaultSubmit(event,\''+id+'\');return false"><div class="input-field"><label class="input-label">Пароль</label><input class="input-text" type="password" id="vault-open-password" placeholder="Введите пароль" required autofocus></div><div class="dialog-actions"><button type="button" class="btn btn-outlined" onclick="closeDialog()">Отмена</button><button type="submit" class="btn btn-filled"><span class="material-symbols-rounded" style="font-size:18px;">lock_open</span>Открыть</button></div></form></div></div>';setTimeout(function(){var el=document.getElementById('vault-open-password');if(el)el.focus();},100);}
function openVaultSubmit(e,id){
    e.preventDefault();
    var btn=document.querySelector('#dialog-container .btn-filled');
    if(btn&&btn.disabled)return;
    
    var pw=document.getElementById('vault-open-password').value;
    if(!pw)return;
    
    if(btn){btn.disabled=true;btn.textContent='...';}
    
    api('open_vault',{vault_id:id,password:pw},function(r){
        if(r.success){
            closeDialog();
            STATE.view='browser';
            STATE.currentVault={id:id,name:r.name};
            STATE.currentPath='/';
            STATE.sessionToken=r.session;
            STATE.locked=false;
            STATE.viewMode='list';
            renderBrowser();
            resetInactivityTimer();
            showToast('Хранилище открыто','lock_open');
        }else{
            showToast(r.error||'Неверный пароль','error');
            var el=document.getElementById('vault-open-password');
            if(el){el.value='';el.focus();}
            
            var msg=r.error||'';
            var match=msg.match(/(\d+)\s*сек/);
            if(match){
                var seconds=parseInt(match[1]);
                lockButton(document.querySelector('#dialog-container .btn-filled'),seconds);
            }else{
                if(btn){btn.disabled=false;btn.textContent='Открыть';}
            }
        }
    });
}
function lockButton(btn,seconds){
    if(!btn)return;
    btn.disabled=true;
    btn.style.opacity='0.5';
    
    function update(){
        if(seconds<=0){
            btn.disabled=false;
            btn.style.opacity='1';
            btn.textContent=btn.closest('#lock-screen')?'Разблокировать':'Открыть';
            return;
        }
        btn.textContent='Ждите '+seconds+' сек';
        seconds--;
        setTimeout(update,1000);
    }
    update();
}
function showCreateFolderDialog(){resetInactivityTimer();document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" onclick="if(event.target===this)closeDialog()"><div class="dialog" onclick="event.stopPropagation()"><div class="dialog-title">Новая папка</div><form onsubmit="createFolderForm(event);return false"><div class="input-field"><label class="input-label">Название</label><input class="input-text" type="text" id="folder-name-input" placeholder="Название папки" required autofocus></div><div class="dialog-actions"><button type="button" class="btn btn-outlined" onclick="closeDialog()">Отмена</button><button type="submit" class="btn btn-filled">Создать</button></div></form></div></div>';}
function createFolderForm(e){e.preventDefault();resetInactivityTimer();var name=document.getElementById('folder-name-input').value.trim();if(!name||name.indexOf('/')!==-1)return;api('create_folder',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath,name:name},function(r){if(r.success){closeDialog();loadFiles();showToast('Папка создана','check_circle');}else showToast(r.error||'Ошибка','error');});}

function showUploadDialog(){resetInactivityTimer();document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" onclick="if(event.target===this)closeDialog()"><div class="dialog" onclick="event.stopPropagation()"><div class="dialog-title">Загрузить файлы (макс. 1 ГБ)</div><form onsubmit="startUpload(event);return false"><div class="input-field"><label class="input-label">Выберите файлы</label><input class="input-text" type="file" id="upload-input" multiple required style="padding:8px 0;"></div><div id="upload-progress" style="margin-top:8px;"></div><div class="dialog-actions"><button type="button" class="btn btn-outlined" onclick="closeDialog()">Отмена</button><button type="submit" class="btn btn-filled" id="upload-btn">Загрузить</button></div></form></div></div>';}
function startUpload(e){e.preventDefault();var files=document.getElementById('upload-input').files;if(!files||!files.length)return;var btn=document.getElementById('upload-btn');btn.disabled=true;btn.textContent='Загрузка...';var total=files.length,done=0,prog=document.getElementById('upload-progress');function next(i){if(i>=total){btn.disabled=false;btn.textContent='Загрузить';closeDialog();loadFiles();showToast('Загружено '+done+' из '+total,'check_circle');return;}prog.innerHTML='<div class="input-helper">Загрузка '+(i+1)+' из '+total+': '+escapeHtml(files[i].name)+'</div>';uploadFile(files[i],function(resp){if(resp.success)done++;next(i+1);});}next(0);}

function downloadFile(filename){resetInactivityTimer();hideContextMenu();if(isExeFile(filename)){showExeWarning(filename);return;}if(window.pywebview&&window.pywebview.api){window.pywebview.api.save_file_dialog(STATE.currentVault.id,STATE.sessionToken,STATE.currentPath,filename);}else{api('download_file',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath,filename:filename},function(resp){if(resp.success&&resp.stream){window.open('/api/stream_file?token='+resp.token,'_blank');}else if(resp.success&&resp.data){try{var bin=atob(resp.data),bytes=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);var blob=new Blob([bytes]),url=URL.createObjectURL(blob);var a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);showToast('Скачано','download');}catch(e){showToast('Ошибка','error');}}else{showToast(resp.error||'Файл не найден','error');}});}}

function renameItemDialog(name,isDir){resetInactivityTimer();hideContextMenu();document.getElementById('dialog-container').innerHTML='<div class="dialog-overlay" onclick="if(event.target===this)closeDialog()"><div class="dialog" onclick="event.stopPropagation()"><div class="dialog-title">Переименовать</div><form onsubmit="renameItemSubmit(event,\''+escapeJsString(name)+'\','+isDir+');return false"><div class="input-field"><label class="input-label">Новое имя</label><input class="input-text" type="text" id="rename-input" value="'+escapeHtml(name)+'" required autofocus></div><div class="dialog-actions"><button type="button" class="btn btn-outlined" onclick="closeDialog()">Отмена</button><button type="submit" class="btn btn-filled">Переименовать</button></div></form></div></div>';}
function renameItemSubmit(e,oldName,isDir){e.preventDefault();var newName=document.getElementById('rename-input').value.trim();if(!newName||newName===oldName){closeDialog();return;}api('rename_item',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath,old_name:oldName,new_name:newName,is_dir:isDir},function(r){if(r.success){closeDialog();loadFiles();showToast('Переименовано','edit');}else showToast(r.error||'Ошибка','error');});}

function deleteItem(name,isDir){resetInactivityTimer();hideContextMenu();if(!confirm('Удалить "'+name+'"?'))return;api('delete_item',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath,name:name,is_dir:isDir},function(r){if(r.success){loadFiles();showToast('Удалено','delete');}else showToast(r.error||'Ошибка','error');});}

function showFileInfo(name,isDir,size,mtime){hideContextMenu();var info='Имя: '+name+'\nТип: '+(isDir?'Папка':'Файл');if(!isDir){info+='\nРазмер: '+formatSize(size);info+='\nИзменён: '+formatDate(mtime);}alert(info);}
function hideContextMenu(){var cm=document.getElementById('context-menu');cm.style.display='none';STATE.contextFile=null;STATE.contextIsDir=false;}

function showContextMenu(e,name,isDir,size,mtime){e.preventDefault();e.stopPropagation();resetInactivityTimer();STATE.contextFile=name;STATE.contextIsDir=isDir;var cm=document.getElementById('context-menu');var items=[];if(!isDir){items.push({icon:'info',label:'Информация',action:'showFileInfo(\''+escapeJsString(name)+'\','+isDir+','+(size||0)+','+(mtime||0)+')'});if(isTextFile(name)||isImageFile(name)||isAudioFile(name)||isVideoFile(name)){items.push({icon:'visibility',label:'Предпросмотр',action:'handleFileDoubleClick(\''+escapeJsString(name)+'\')'});}items.push({icon:'download',label:'Скачать',action:'downloadFile(\''+escapeJsString(name)+'\')'});}items.push({icon:'edit',label:'Переименовать',action:'renameItemDialog(\''+escapeJsString(name)+'\','+isDir+')'});items.push({icon:'delete',label:'Удалить',action:'deleteItem(\''+escapeJsString(name)+'\','+isDir+')'});var h='';for(var i=0;i<items.length;i++){h+='<div class="context-menu-item" onclick="'+items[i].action+'"><span class="material-symbols-rounded">'+items[i].icon+'</span>'+items[i].label+'</div>';}cm.innerHTML=h;cm.style.display='block';var x=e.clientX,y=e.clientY;if(x+200>window.innerWidth)x=window.innerWidth-210;if(y+items.length*40>window.innerHeight)y=window.innerHeight-items.length*40-10;cm.style.left=x+'px';cm.style.top=y+'px';}

document.addEventListener('click',function(e){resetInactivityTimer();if(!e.target.closest('.context-menu'))hideContextMenu();});
document.addEventListener('contextmenu',function(e){if(!e.target.closest('.file-item')&&!e.target.closest('.file-card'))hideContextMenu();});

function renderVaults(){document.getElementById('app').innerHTML='<div class="app-bar"><div class="app-bar-leading"><span class="material-symbols-rounded" style="color:var(--md-primary);font-size:28px;">encrypted</span></div><div class="app-bar-headline">EveryCrypt</div><div class="app-bar-actions"><button class="btn-icon" onclick="renderSettings()" title="Настройки"><span class="material-symbols-rounded">settings</span></button></div></div><div class="content"><div class="card-title" style="margin-top:8px;">Мои хранилища</div><div id="vaults-list"><div class="empty-state"><span class="material-symbols-rounded">hourglass</span><div class="empty-state-text">Загрузка...</div></div></div></div><button class="fab" onclick="showCreateVaultDialog()" title="Новое хранилище"><span class="material-symbols-rounded">add</span></button><div id="dialog-container"></div>';loadVaults();}

function renderSettings(){document.getElementById('app').innerHTML='<div class="app-bar"><div class="app-bar-leading"><button class="btn-icon" onclick="renderVaults()" aria-label="Назад"><span class="material-symbols-rounded">arrow_back</span></button></div><div class="app-bar-headline">Настройки</div></div><div class="content"><div class="card"><div class="card-title">Внешний вид</div><div class="switch-container"><span>Тёмная тема</span><label class="switch"><input type="checkbox" id="dark-switch" onchange="toggleTheme()" '+(STATE.theme==='dark'?'checked':'')+'><span class="slider"></span></label></div></div><div class="card"><div class="card-title">Безопасность</div><div class="switch-container"><div><span>Доступ только из приложения</span><div style="font-size:12px;color:var(--md-on-surface-variant);margin-top:4px;">Блокирует доступ из браузеров</div></div><label class="switch"><input type="checkbox" id="block-switch" onchange="toggleBlocking()"><span class="slider"></span></label></div><div class="divider"></div><div class="input-field" style="margin-top:16px;"><label class="input-label">Автоблокировка при неактивности</label><select class="sort-select" id="lock-timeout-select" onchange="changeLockTimeout()" style="width:70%;"><option value="10">10 секунд</option><option value="25">25 секунд</option><option value="30">30 секунд</option><option value="60">1 минута</option><option value="120">2 минуты</option><option value="300">5 минут</option><option value="600">10 минут</option><option value="1800">30 минут</option><option value="0">Отключить</option></select></div></div><div class="card"><div class="card-title">О программе</div><div style="font-size:14px;color:var(--md-on-surface-variant);line-height:1.8"><p>EveryCrypt v2.1</p><p>Защищённое файловое хранилище</p><p>Argon2id + ChaCha20-Poly1305</p><div style="display:flex;align-items:center;gap:12px;margin-top:12px;"><a href="https://github.com/everycrypt" target="_blank" style="display:inline-block;"><img src="/static/img/etc/github_button.png" alt="GitHub" style="height:64px;border-radius:6px;cursor:pointer;"></a><img src="/static/img/etc/gpl.png" alt="GPL v3" style="height:64px;"></div></div></div></div><div id="dialog-container"></div>';api('get_blocking_mode',{},function(r){if(r.success){document.getElementById('block-switch').checked=r.block_browsers;}});api('get_lock_timeout',{},function(r){if(r.success){STATE.lockTimeout=r.timeout;var sel=document.getElementById('lock-timeout-select');if(sel)sel.value=r.timeout;}});}

function toggleBlocking(){var enabled=document.getElementById('block-switch').checked;api('set_blocking_mode',{enabled:enabled},function(r){if(r.success){showToast(enabled?'Браузеры заблокированы':'Доступ открыт','shield');}});}
function changeLockTimeout(){var timeout=parseInt(document.getElementById('lock-timeout-select').value);STATE.lockTimeout=timeout;api('set_lock_timeout',{timeout:timeout},function(r){if(r.success){showToast(timeout>0?'Время блокировки: '+timeout+' сек.':'Блокировка отключена','timer');}});}

function renderBrowser(){var name=STATE.currentVault?STATE.currentVault.name:'';thumbnailUrls={};document.getElementById('app').innerHTML='<div class="app-bar"><div class="app-bar-leading"><button class="btn-icon" onclick="goBack()" aria-label="Назад"><span class="material-symbols-rounded">arrow_back</span></button></div><div class="app-bar-headline">'+escapeHtml(name)+'</div><div class="app-bar-actions"><div class="view-toggle" id="view-toggle"><button class="btn-icon active" onclick="setViewMode(\'list\')" title="Список"><span class="material-symbols-rounded">view_list</span></button><button class="btn-icon" onclick="setViewMode(\'grid\')" title="Иконки"><span class="material-symbols-rounded">grid_view</span></button><button class="btn-icon" onclick="setViewMode(\'grid-large\')" title="Крупные"><span class="material-symbols-rounded">view_module</span></button><button class="btn-icon" onclick="setViewMode(\'grid-small\')" title="Мелкие"><span class="material-symbols-rounded">apps</span></button></div></div></div><div class="content"><div class="breadcrumbs" id="breadcrumbs"></div><div class="card"><div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;align-items:center;"><button class="btn btn-tonal" onclick="showCreateFolderDialog()"><span class="material-symbols-rounded">create_new_folder</span>Папка</button><button class="btn btn-tonal" onclick="showUploadDialog()"><span class="material-symbols-rounded">upload_file</span>Загрузить</button><select class="sort-select" onchange="sortFiles(this.value)" style="margin-left:auto;"><option value="name_asc">Имя ↑</option><option value="name_desc">Имя ↓</option><option value="size_asc">Размер ↑</option><option value="size_desc">Размер ↓</option><option value="date_asc">Дата ↑</option><option value="date_desc">Дата ↓</option><option value="type_asc">Тип ↑</option><option value="type_desc">Тип ↓</option></select></div><div class="divider"></div><div id="file-list-container" class="file-list-container"><ul class="file-list" id="file-list"><li class="empty-state"><span class="material-symbols-rounded">folder_open</span><div class="empty-state-text">Загрузка...</div></li></ul></div></div></div><div id="dialog-container"></div>';renderBreadcrumbs();loadFiles();}

function renderBreadcrumbs(){var c=document.getElementById('breadcrumbs');if(!c)return;var parts=STATE.currentPath.split('/').filter(Boolean);var h='<span class="breadcrumb" onclick="navigateTo(\'/\')"><span class="material-symbols-rounded" style="font-size:18px;">home</span></span>';var p='';for(var i=0;i<parts.length;i++){p+='/'+parts[i];h+='<span class="breadcrumb-sep">&rsaquo;</span>';h+=i===parts.length-1?'<span class="breadcrumb breadcrumb-active">'+escapeHtml(parts[i])+'</span>':'<span class="breadcrumb" onclick="navigateTo(\''+escapeJsString(p)+'\')">'+escapeHtml(parts[i])+'</span>';}c.innerHTML=h;}

function renderFileList(){var files=STATE.files,dirs=STATE.dirs;var container=document.getElementById('file-list');if(!container)return;var mode=STATE.viewMode||'list';var vt=document.getElementById('view-toggle');if(vt){vt.querySelectorAll('.btn-icon').forEach(function(b){b.classList.remove('active');});var ab=vt.querySelector('[onclick*="'+mode+'"]');if(ab)ab.classList.add('active');}var emptyHTML='<div class="empty-state"><span class="material-symbols-rounded">folder_open</span><div class="empty-state-text">Пустая папка</div></div>';if(dirs.length===0&&files.length===0){if(mode==='list'){container.parentElement.innerHTML='<ul class="file-list" id="file-list"></ul>';}else{var gc='file-grid';if(mode==='grid-large')gc='file-grid file-grid-large';else if(mode==='grid-small')gc='file-grid file-grid-small';container.parentElement.innerHTML='<div class="'+gc+'" id="file-list"></div>';}document.getElementById('file-list').innerHTML=emptyHTML;return;}if(mode==='list'){container.parentElement.innerHTML='<ul class="file-list" id="file-list"></ul>';container=document.getElementById('file-list');var h='';for(var i=0;i<dirs.length;i++){var d=dirs[i],dp=STATE.currentPath==='/'?'/'+d:STATE.currentPath+'/'+d;h+='<li class="file-item" ondblclick="navigateTo(\''+escapeJsString(dp)+'\')" onclick="resetInactivityTimer()" oncontextmenu="showContextMenu(event,\''+escapeJsString(d)+'\',true,0,0)"><div class="file-item-leading"><span class="material-symbols-rounded">folder</span></div><div class="file-item-content"><div class="file-item-name">'+escapeHtml(d)+'</div><div class="file-item-meta">Папка</div></div><div class="file-item-trailing"><button class="btn-icon" onclick="event.stopPropagation();navigateTo(\''+escapeJsString(dp)+'\')" aria-label="Открыть"><span class="material-symbols-rounded">open_in_new</span></button><button class="btn-icon" onclick="event.stopPropagation();deleteItem(\''+escapeJsString(d)+'\',true)" aria-label="Удалить"><span class="material-symbols-rounded">delete</span></button></div></li>';}for(var j=0;j<files.length;j++){var f=files[j],en=escapeJsString(f.name),isImg=isImageFile(f.name);h+='<li class="file-item" ondblclick="handleFileDoubleClick(\''+en+'\')" onclick="resetInactivityTimer()" oncontextmenu="showContextMenu(event,\''+en+'\',false,'+f.size+','+(f.mtime||0)+')"><div class="file-item-leading" id="lead-'+j+'"><span class="material-symbols-rounded">'+(isImg?'image':(isTextFile(f.name)?'description':(isAudioFile(f.name)?'music_note':(isVideoFile(f.name)?'movie':'insert_drive_file'))))+'</span></div><div class="file-item-content"><div class="file-item-name">'+escapeHtml(f.name)+'</div><div class="file-item-meta">'+formatSize(f.size)+' · '+formatDate(f.mtime)+'</div></div><div class="file-item-trailing">';if(isImg||isTextFile(f.name))h+='<button class="btn-icon" onclick="event.stopPropagation();handleFileDoubleClick(\''+en+'\')" aria-label="Предпросмотр"><span class="material-symbols-rounded">visibility</span></button>';h+='<button class="btn-icon" onclick="event.stopPropagation();downloadFile(\''+en+'\')" aria-label="Скачать"><span class="material-symbols-rounded">download</span></button><button class="btn-icon" onclick="event.stopPropagation();deleteItem(\''+en+'\',false)" aria-label="Удалить"><span class="material-symbols-rounded">delete</span></button></div></li>';}container.innerHTML=h;for(var j=0;j<files.length;j++){var f=files[j];if(isImageFile(f.name)){(function(idx,fname,lid){getThumbnailUrl(fname,function(url){if(url){var l=document.getElementById(lid);if(l)l.innerHTML='<img src="'+url+'" onerror="this.style.display=\'none\';this.parentElement.innerHTML=\'<span class=material-symbols-rounded>image</span>\'" alt="">';}});})(j,f.name,'lead-'+j);}}}else{var gc='file-grid';if(mode==='grid-large')gc='file-grid file-grid-large';else if(mode==='grid-small')gc='file-grid file-grid-small';container.parentElement.innerHTML='<div class="'+gc+'" id="file-list"></div>';container=document.getElementById('file-list');var g='';for(var i=0;i<dirs.length;i++){var d=dirs[i],dp=STATE.currentPath==='/'?'/'+d:STATE.currentPath+'/'+d;g+='<div class="file-card" ondblclick="navigateTo(\''+escapeJsString(dp)+'\')" onclick="resetInactivityTimer()" oncontextmenu="showContextMenu(event,\''+escapeJsString(d)+'\',true,0,0)"><div class="file-icon"><span class="material-symbols-rounded">folder</span></div><span class="file-name">'+escapeHtml(d)+'</span></div>';}for(var j=0;j<files.length;j++){var f=files[j],en=escapeJsString(f.name),isImg=isImageFile(f.name);g+='<div class="file-card" ondblclick="handleFileDoubleClick(\''+en+'\')" onclick="resetInactivityTimer()" oncontextmenu="showContextMenu(event,\''+en+'\',false,'+f.size+','+(f.mtime||0)+')"><div class="file-icon" id="gicon-'+j+'"><span class="material-symbols-rounded">'+(isImg?'image':(isTextFile(f.name)?'description':(isAudioFile(f.name)?'music_note':(isVideoFile(f.name)?'movie':'insert_drive_file'))))+'</span></div><span class="file-name">'+escapeHtml(f.name)+'</span></div>';}container.innerHTML=g;for(var j=0;j<files.length;j++){var f=files[j];if(isImageFile(f.name)){(function(idx,fname,iid){getThumbnailUrl(fname,function(url){if(url){var ic=document.getElementById(iid);if(ic)ic.innerHTML='<img src="'+url+'" onerror="this.style.display=\'none\';this.parentElement.innerHTML=\'<span class=material-symbols-rounded>image</span>\'" alt="">';}});})(j,f.name,'gicon-'+j);}}}}
function loadVaults(){api('list_vaults',{},function(r){var c=document.getElementById('vaults-list');if(!c)return;if(!r.success||!r.vaults||!r.vaults.length){c.innerHTML='<div class="empty-state"><span class="material-symbols-rounded">encrypted_off</span><div class="empty-state-text">Нет хранилищ</div></div>';return;}var h='<div class="grid">';for(var i=0;i<r.vaults.length;i++){var v=r.vaults[i];h+='<div class="card" style="cursor:pointer" onclick="openVaultDialog(\''+v.id+'\')"><div style="display:flex;align-items:center;gap:16px;"><span class="material-symbols-rounded" style="font-size:40px;color:var(--md-primary);">encrypted</span><div style="flex:1;min-width:0;"><div style="font-weight:500;">'+escapeHtml(v.name_hint)+'</div><div style="font-size:12px;color:var(--md-on-surface-variant);">Создано: '+escapeHtml(v.created_at||'')+'</div></div></div></div>';}h+='</div>';c.innerHTML=h;});}
function loadFiles(){api('list_files',{vault_id:STATE.currentVault.id,session:STATE.sessionToken,path:STATE.currentPath},function(r){if(r.success){STATE.files=r.files||[];STATE.dirs=r.dirs||[];renderFileList();}else{showToast('Ошибка загрузки','error');STATE.currentPath='/';loadFiles();}});}

function init(){STATE.view='vaults';STATE.currentPath='/';renderVaults();}
document.addEventListener('click',function(){resetInactivityTimer();});
document.addEventListener('keydown',function(e){
    resetInactivityTimer();
    if(e.key==='Escape'||e.keyCode===27){closeDialog();}
});
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
</script>
</body>
</html>'''

# ─── Маршруты ────────────────────────────────────
@app.route('/')
def index():
    html_with_token = HTML.replace('var APP_TOKEN=\'{APP_TOKEN}\';', f'var APP_TOKEN=\'{APP_SECRET_TOKEN}\';')
    return render_template_string(html_with_token)

@app.route('/api/get_theme', methods=['GET'])
def get_theme():
    theme = load_theme_from_file()
    return jsonify({'success': True, 'theme': theme})

@app.route('/api/save_theme', methods=['POST'])
def save_theme():
    data = request.get_json(force=True, silent=True) or {}
    theme = data.get('theme', 'light')
    if theme not in ('light', 'dark'): theme = 'light'
    save_theme_to_file(theme)
    return jsonify({'success': True})

@app.route('/api/<method>', methods=['POST'])
def api_handler(method):
    try:
        data = request.get_json(force=True, silent=True) or {}
        if method == 'create_vault': return handle_create_vault(data)
        if method == 'list_vaults': return handle_list_vaults(data)
        if method == 'open_vault': return handle_open_vault(data)
        if method == 'list_files': return handle_list_files(data)
        if method == 'create_folder': return handle_create_folder(data)
        if method == 'delete_item': return handle_delete_item(data)
        if method == 'download_file': return handle_download_file(data)
        if method == 'get_preview_token': return handle_get_preview_token(data)
        if method == 'get_thumbnail_token': return handle_get_thumbnail_token(data)
        if method == 'rename_item': return handle_rename_item(data)
        if method == 'get_blocking_mode': return handle_get_blocking_mode(data)
        if method == 'set_blocking_mode': return handle_set_blocking_mode(data)
        if method == 'get_lock_timeout': return handle_get_lock_timeout(data)
        if method == 'set_lock_timeout': return handle_set_lock_timeout(data)
        return jsonify({'success': False, 'error': 'Неизвестный метод'})
    except Exception as e:
        logger.error(f"API error in {method}")
        return jsonify({'success': False, 'error': 'Ошибка сервера'})

@app.route('/api/upload_file', methods=['POST'])
def handle_upload_file():
    try:
        vid = request.form.get('vault_id'); tok = request.form.get('session')
        file = request.files.get('file'); path = request.form.get('path', '/')
        if not all([vid, tok, file]): return jsonify({'success': False, 'error': 'Нет данных'})
        if tok not in active_sessions: return jsonify({'success': False, 'error': 'Сессия истекла'})
        vault = active_sessions[tok]; vault['last_active'] = time.time()
        keys = vault['keys']
        file.seek(0, 2); size = file.tell(); file.seek(0)
        if size > MAX_FILE_SIZE: return jsonify({'success': False, 'error': f'Файл больше {MAX_FILE_SIZE // (1024*1024)} МБ'})
        data = file.read(); fname = normalize_filename(file.filename)
        mapping = load_mapping(vault['path'], keys['map_key'])
        real_path = find_real_path(mapping, path, keys['enc_key'])
        if real_path not in mapping: return jsonify({'success': False, 'error': 'Путь не существует'})
        for info in mapping[real_path].get('files', {}).values():
            if info['name_enc'] == base64.b64encode(encrypt_data(fname.encode(), keys['enc_key'])).decode('ascii'):
                return jsonify({'success': False, 'error': 'Файл с таким именем уже существует'})
        enc_name = encrypt_data(fname.encode(), keys['enc_key']); enc_body = encrypt_data(data, keys['enc_key'])
        fid = secrets.token_hex(16); ep = vault['path'] / (fid + '.enc')
        ep.write_bytes(len(enc_name).to_bytes(4, 'big') + enc_name + enc_body)
        mapping[real_path]['files'][fid] = {'name_enc': base64.b64encode(enc_name).decode('ascii'), 'size': size, 'enc_path': fid + '.enc'}
        save_mapping(vault['path'], mapping, keys['map_key'])
        return jsonify({'success': True})
    except ValueError as e: return jsonify({'success': False, 'error': str(e)})
    except Exception as e: logger.error("Upload error"); return jsonify({'success': False, 'error': 'Ошибка загрузки'})

@app.route('/api/thumbnail')
def thumbnail():
    token = request.args.get('token')
    if not token or token not in thumbnail_tokens: return 'Token invalid', 403
    info = thumbnail_tokens[token]
    if time.time() - info.get('created', 0) > THUMBNAIL_TOKEN_TTL: thumbnail_tokens.pop(token, None); return 'Token expired', 403
    try:
        vault = active_sessions.get(info['session'])
        if not vault: thumbnail_tokens.pop(token, None); return 'Session expired', 403
        keys = vault['keys']; mapping = load_mapping(vault['path'], keys['map_key'])
        real_path = find_real_path(mapping, info['path'], keys['enc_key'])
        if real_path not in mapping: thumbnail_tokens.pop(token, None); return 'Path not found', 404
        for fid, finfo in mapping[real_path].get('files', {}).items():
            if finfo['name_enc'] == info['name_enc']:
                ep = vault['path'] / finfo['enc_path']
                if not ep.exists(): thumbnail_tokens.pop(token, None); return 'File not found', 404
                raw = ep.read_bytes(); nl = int.from_bytes(raw[:4], 'big'); dec = decrypt_data(raw[4+nl:], keys['enc_key'])
                if not is_image_ext(decrypt_data(base64.b64decode(finfo['name_enc']), keys['enc_key']).decode()):
                    thumbnail_tokens.pop(token, None); return 'Not an image', 415
                thumb = generate_thumbnail(dec)
                if thumb: thumbnail_tokens.pop(token, None); return Response(thumb, mimetype='image/jpeg')
                return 'Thumbnail failed', 500
        thumbnail_tokens.pop(token, None); return 'File not found', 404
    except Exception as e: logger.error(f"Thumbnail: {e}"); thumbnail_tokens.pop(token, None); return 'Error', 500

@app.route('/api/preview_image')
def preview_image():
    token = request.args.get('token')
    if not token or token not in preview_tokens: return 'Token invalid', 403
    info = preview_tokens.pop(token)
    if time.time() - info.get('created', 0) > PREVIEW_TOKEN_TTL: return 'Token expired', 403
    try:
        vault = active_sessions.get(info['session'])
        if not vault: return 'Session expired', 403
        keys = vault['keys']; mapping = load_mapping(vault['path'], keys['map_key'])
        real_path = find_real_path(mapping, info['path'], keys['enc_key'])
        if real_path not in mapping: return 'Path not found', 404
        for fid, finfo in mapping[real_path].get('files', {}).items():
            if finfo['name_enc'] == info['name_enc']:
                ep = vault['path'] / finfo['enc_path']
                if not ep.exists(): return 'File not found', 404
                raw = ep.read_bytes(); nl = int.from_bytes(raw[:4], 'big'); dec = decrypt_data(raw[4+nl:], keys['enc_key'])
                orig_name = decrypt_data(base64.b64decode(finfo['name_enc']), keys['enc_key']).decode()
                mime, _ = mimetypes.guess_type(orig_name)
                if not mime: mime = 'application/octet-stream'
                return Response(dec, mimetype=mime)
        return 'File not found', 404
    except Exception as e: logger.error("Preview error"); return 'Error', 500

def handle_get_thumbnail_token(data):
    tok = data.get('session'); path = data.get('path', '/'); filename = data.get('filename')
    if tok not in active_sessions: return jsonify({'success': False, 'error': 'Сессия истекла'})
    vault = active_sessions[tok]; vault['last_active'] = time.time()
    mapping = load_mapping(vault['path'], vault['keys']['map_key'])
    real_path = find_real_path(mapping, path, vault['keys']['enc_key'])
    if real_path not in mapping: return jsonify({'success': False, 'error': 'Путь не существует'})
    found = None
    for fid, finfo in mapping[real_path].get('files', {}).items():
        try:
            if decrypt_data(base64.b64decode(finfo['name_enc']), vault['keys']['enc_key']).decode() == filename:
                found = finfo['name_enc']; break
        except: pass
    if not found: return jsonify({'success': False, 'error': 'Файл не найден'})
    token = secrets.token_hex(32)
    thumbnail_tokens[token] = {'session': tok, 'path': path, 'name_enc': found, 'created': time.time()}
    return jsonify({'success': True, 'token': token})

def handle_get_preview_token(data):
    tok = data.get('session'); path = data.get('path', '/'); filename = data.get('filename')
    if tok not in active_sessions: return jsonify({'success': False, 'error': 'Сессия истекла'})
    vault = active_sessions[tok]; vault['last_active'] = time.time()
    mapping = load_mapping(vault['path'], vault['keys']['map_key'])
    real_path = find_real_path(mapping, path, vault['keys']['enc_key'])
    if real_path not in mapping: return jsonify({'success': False, 'error': 'Путь не существует'})
    found = None
    for fid, finfo in mapping[real_path].get('files', {}).items():
        try:
            if decrypt_data(base64.b64decode(finfo['name_enc']), vault['keys']['enc_key']).decode() == filename:
                found = finfo['name_enc']; break
        except: pass
    if not found: return jsonify({'success': False, 'error': 'Файл не найден'})
    token = secrets.token_hex(32)
    preview_tokens[token] = {'session': tok, 'path': path, 'name_enc': found, 'created': time.time()}
    return jsonify({'success': True, 'token': token})

def handle_create_vault(data):
    name = data.get('name', '').strip(); pw = data.get('password', '')
    encrypt_name = data.get('encrypt_name', False)
    if not name or not pw: return jsonify({'success': False, 'error': 'Заполните имя и пароль'})
    if len(pw) < 8: return jsonify({'success': False, 'error': 'Пароль минимум 8 символов'})
    try:
        pepper = load_or_create_pepper(); v = create_vault(name, pw, pepper, encrypt_name)
        return jsonify({'success': True, 'vault': v})
    except Exception as e: return jsonify({'success': False, 'error': 'Ошибка создания хранилища'})

def handle_list_vaults(data=None):
    vaults = []
    for item in CACHE_DIR.iterdir():
        if item.is_dir() and (item / 'header.crypt').exists():
            try:
                raw = (item / 'header.crypt').read_bytes()
                if b'\n--SIG--\n' in raw:
                    h = json.loads(raw.split(b'\n--SIG--\n')[0])
                    name_hint = h.get('name_hint', f'Хранилище {item.name[:8]}')
                    vaults.append({'id': item.name, 'created_at': h.get('created_at', ''), 'name_hint': name_hint})
            except: pass
    vaults.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({'success': True, 'vaults': vaults})


# ─── Защита от брутфорса (сохранение попыток) ────

LOGIN_ATTEMPTS_FILE = BASE_DIR / "login_attempts.json"
LOGIN_FILE_KEY = None

def load_login_attempts() -> dict:
    """Загружает попытки входа из защищённого файла"""
    global LOGIN_FILE_KEY
    if LOGIN_FILE_KEY is None:
        key_file = BASE_DIR / "login_attempts.key"
        if key_file.exists():
            LOGIN_FILE_KEY = key_file.read_bytes()
        else:
            LOGIN_FILE_KEY = secrets.token_bytes(32)
            key_file.write_bytes(LOGIN_FILE_KEY)
    
    if LOGIN_ATTEMPTS_FILE.exists():
        try:
            encrypted = LOGIN_ATTEMPTS_FILE.read_bytes()
            decrypted = decrypt_data(encrypted, LOGIN_FILE_KEY)
            return json.loads(decrypted.decode('utf-8'))
        except:
            pass
    return {}

def save_login_attempts(attempts: dict):
    """Сохраняет попытки входа в защищённый файл"""
    global LOGIN_FILE_KEY
    if LOGIN_FILE_KEY is None:
        key_file = BASE_DIR / "login_attempts.key"
        if key_file.exists():
            LOGIN_FILE_KEY = key_file.read_bytes()
        else:
            LOGIN_FILE_KEY = secrets.token_bytes(32)
            key_file.write_bytes(LOGIN_FILE_KEY)
    
    encrypted = encrypt_data(json.dumps(attempts).encode('utf-8'), LOGIN_FILE_KEY)
    LOGIN_ATTEMPTS_FILE.write_bytes(encrypted)

# fixed 


def handle_open_vault(data):
    vid = data.get('vault_id')
    pw = data.get('password', '')
    client_ip = request.remote_addr
    
    if not vid or not pw:
        return jsonify({'success': False, 'error': 'Введите пароль'})
    
    now = time.time()
    attempt_key = f"{client_ip}:{vid}"
    attempts_file = BASE_DIR / "brute_force_protection.dat"
    key_file = BASE_DIR / "brute_force.key"
    
    # Ключ для шифрования попыток
    if key_file.exists():
        key = key_file.read_bytes()
    else:
        key = secrets.token_bytes(32)
        key_file.write_bytes(key)
    
    # Загружаем попытки
    saved = {}
    if attempts_file.exists():
        try:
            decrypted = decrypt_data(attempts_file.read_bytes(), key)
            saved = json.loads(decrypted.decode('utf-8'))
        except:
            pass
    
    # Проверяем блокировку
    if attempt_key in saved:
        ad = saved[attempt_key]
        count = ad.get('c', 0)
        last = ad.get('t', 0)
        blocked = ad.get('b', 0)
        
        # Заблокирован?
        if blocked > now:
            remaining = int(blocked - now)
            hours = remaining // 3600
            mins = (remaining % 3600) // 60
            secs = remaining % 60
            if hours > 0:
                msg = f'Доступ заблокирован на {hours} ч {mins} мин.'
            elif mins > 0:
                msg = f'Доступ заблокирован на {mins} мин {secs} сек.'
            else:
                msg = f'Доступ заблокирован на {secs} сек.'
            return jsonify({'success': False, 'error': msg})
        
        # Задержка?
        delays = {3: 5, 4: 30, 5: 300, 6: 900, 7: 3600, 8: 10800, 9: 86400}
        if count >= 3:
            delay = delays.get(count, 86400)
            elapsed = now - last
            if elapsed < delay:
                remaining = int(delay - elapsed)
                # РЕАЛЬНАЯ ЗАДЕРЖКА
                time.sleep(min(remaining, 10))  # Максимум 10 сек ожидания
                if remaining >= 3600:
                    msg = f'Подождите {remaining//3600} ч {(remaining%3600)//60} мин.'
                elif remaining >= 60:
                    msg = f'Подождите {remaining//60} мин {remaining%60} сек.'
                else:
                    msg = f'Подождите {remaining} сек.'
                return jsonify({'success': False, 'error': msg})
    
    try:
        pepper = load_or_create_pepper()
        vault = open_vault(vid, pw, pepper)
        
        if not vault:
            if attempt_key not in saved:
                saved[attempt_key] = {'c': 0, 't': 0, 'b': 0}
            
            saved[attempt_key]['c'] += 1
            saved[attempt_key]['t'] = now
            count = saved[attempt_key]['c']
            
            # Блокировка после 10 попыток
            if count >= 10:
                saved[attempt_key]['b'] = now + 86400
                attempts_file.write_bytes(encrypt_data(json.dumps(saved).encode(), key))
                return jsonify({'success': False, 'error': '10 неверных попыток. Доступ заблокирован на 24 часа.'})
            
            # Сохраняем
            attempts_file.write_bytes(encrypt_data(json.dumps(saved).encode(), key))
            
            # Сообщения
            if count <= 3:
                return jsonify({'success': False, 'error': f'Неверный пароль. Осталось попыток: {3-count}'})
            elif count == 4:
                return jsonify({'success': False, 'error': 'Неверный пароль. Ждите 5 сек.'})
            elif count == 5:
                return jsonify({'success': False, 'error': 'Неверный пароль. Ждите 30 сек.'})
            elif count == 6:
                return jsonify({'success': False, 'error': 'Неверный пароль. Ждите 5 мин.'})
            elif count == 7:
                return jsonify({'success': False, 'error': 'Неверный пароль. Ждите 15 мин.'})
            elif count == 8:
                return jsonify({'success': False, 'error': 'Неверный пароль. Ждите 1 час.'})
            elif count == 9:
                return jsonify({'success': False, 'error': 'ПОСЛЕДНЯЯ попытка! Ждите 3 часа.'})
            else:
                return jsonify({'success': False, 'error': f'Неверный пароль. Попытка {count}.'})
        
        # Успех
        if attempt_key in saved:
            del saved[attempt_key]
            attempts_file.write_bytes(encrypt_data(json.dumps(saved).encode(), key))
        
        tok = secrets.token_hex(32)
        active_sessions[tok] = {
            'id': vault['id'], 'name': vault['name'],
            'keys': vault['keys'], 'path': vault['path'],
            'last_active': now
        }
        return jsonify({'success': True, 'name': vault['name'], 'session': tok})
        
    except Exception as e:
        logger.error(f"Vault error: {e}")
        return jsonify({'success': False, 'error': 'Ошибка сервера'})



#fixed

def handle_list_files(data):
    tok = data.get('session'); path = data.get('path', '/')
    if tok not in active_sessions: return jsonify({'success': False, 'error': 'Сессия истекла'})
    vault = active_sessions[tok]; vault['last_active'] = time.time()
    m = load_mapping(vault['path'], vault['keys']['map_key'])
    real_path = find_real_path(m, path, vault['keys']['enc_key'])
    if real_path not in m: return jsonify({'success': False, 'error': 'Путь не существует'})
    entry = m[real_path]; files = []
    for fid, i in entry.get('files', {}).items():
        try: name = decrypt_data(base64.b64decode(i['name_enc']), vault['keys']['enc_key']).decode()
        except: name = '???'
        ep = vault['path'] / i['enc_path']
        mtime = ep.stat().st_mtime if ep.exists() else 0
        files.append({'id': fid, 'name': name, 'size': i['size'], 'mtime': mtime})
    dirs = []
    for d in entry.get('dirs', []):
        try: dirs.append(decrypt_data(base64.b64decode(d), vault['keys']['enc_key']).decode())
        except: pass
    return jsonify({'success': True, 'files': files, 'dirs': dirs})

def handle_create_folder(data):
    tok = data.get('session'); name = data.get('name', '').strip(); path = data.get('path', '/')
    if not name: return jsonify({'success': False, 'error': 'Введите имя'})
    try: name = normalize_filename(name)
    except ValueError as e: return jsonify({'success': False, 'error': str(e)})
    if '/' in name: return jsonify({'success': False, 'error': 'Имя не должно содержать "/"'})
    if name in ('.', '..'): return jsonify({'success': False, 'error': 'Запрещённое имя папки'})
    if tok not in active_sessions: return jsonify({'success': False, 'error': 'Сессия истекла'})
    vault = active_sessions[tok]; vault['last_active'] = time.time()
    m = load_mapping(vault['path'], vault['keys']['map_key'])
    real_path = find_real_path(m, path, vault['keys']['enc_key'])
    if real_path not in m: return jsonify({'success': False, 'error': 'Родительская папка не существует'})
    for enc_dir in m[real_path].get('dirs', []):
        try:
            if decrypt_data(base64.b64decode(enc_dir), vault['keys']['enc_key']).decode() == name:
                return jsonify({'success': False, 'error': 'Папка с таким именем уже существует'})
        except: pass
    for finfo in m[real_path].get('files', {}).values():
        try:
            if decrypt_data(base64.b64decode(finfo['name_enc']), vault['keys']['enc_key']).decode() == name:
                return jsonify({'success': False, 'error': 'Файл с таким именем уже существует'})
        except: pass
    enc_name = base64.b64encode(encrypt_data(name.encode(), vault['keys']['enc_key'])).decode('ascii')
    if enc_name in m[real_path].get('dirs', []): return jsonify({'success': False, 'error': 'Папка уже существует'})
    m[real_path].setdefault('dirs', []).append(enc_name)
    new_path = real_path.rstrip('/') + '/' + enc_name
    if new_path not in m: m[new_path] = {'files': {}, 'dirs': []}
    save_mapping(vault['path'], m, vault['keys']['map_key'])
    return jsonify({'success': True})

def handle_delete_item(data):
    tok = data.get('session'); name = data.get('name'); is_dir = data.get('is_dir', False); path = data.get('path', '/')
    if tok not in active_sessions: return jsonify({'success': False, 'error': 'Сессия истекла'})
    vault = active_sessions[tok]; vault['last_active'] = time.time()
    m = load_mapping(vault['path'], vault['keys']['map_key'])
    real_path = find_real_path(m, path, vault['keys']['enc_key'])
    if real_path not in m: return jsonify({'success': False, 'error': 'Путь не существует'})
    if is_dir:
        for enc_d in list(m[real_path].get('dirs', [])):
            try:
                if decrypt_data(base64.b64decode(enc_d), vault['keys']['enc_key']).decode() == name:
                    m[real_path]['dirs'].remove(enc_d)
                    dir_path = real_path.rstrip('/') + '/' + enc_d
                    if dir_path in m: del m[dir_path]
                    break
            except: pass
    else:
        for fid, inf in list(m[real_path].get('files', {}).items()):
            try:
                if decrypt_data(base64.b64decode(inf['name_enc']), vault['keys']['enc_key']).decode() == name:
                    ep = vault['path'] / inf['enc_path']
                    if ep.exists():
                        with open(ep, 'wb') as f: f.write(secrets.token_bytes(1024))
                        ep.unlink()
                    del m[real_path]['files'][fid]; break
            except: pass
    save_mapping(vault['path'], m, vault['keys']['map_key'])
    return jsonify({'success': True})

def handle_rename_item(data):
    tok = data.get('session'); old_name = data.get('old_name'); new_name = data.get('new_name', '').strip()
    is_dir = data.get('is_dir', False); path = data.get('path', '/')
    if not old_name or not new_name: return jsonify({'success': False, 'error': 'Введите имя'})
    if tok not in active_sessions: return jsonify({'success': False, 'error': 'Сессия истекла'})
    try: new_name = normalize_filename(new_name)
    except ValueError as e: return jsonify({'success': False, 'error': str(e)})
    vault = active_sessions[tok]; vault['last_active'] = time.time()
    m = load_mapping(vault['path'], vault['keys']['map_key'])
    real_path = find_real_path(m, path, vault['keys']['enc_key'])
    if real_path not in m: return jsonify({'success': False, 'error': 'Путь не существует'})
    if is_dir:
        for enc_d in m[real_path].get('dirs', []):
            try:
                if decrypt_data(base64.b64decode(enc_d), vault['keys']['enc_key']).decode() == old_name:
                    new_enc = base64.b64encode(encrypt_data(new_name.encode(), vault['keys']['enc_key'])).decode('ascii')
                    m[real_path]['dirs'].remove(enc_d); m[real_path]['dirs'].append(new_enc)
                    old_dir_path = real_path.rstrip('/') + '/' + enc_d
                    new_dir_path = real_path.rstrip('/') + '/' + new_enc
                    if old_dir_path in m: m[new_dir_path] = m.pop(old_dir_path)
                    break
            except: pass
    else:
        for fid, inf in m[real_path].get('files', {}).items():
            try:
                if decrypt_data(base64.b64decode(inf['name_enc']), vault['keys']['enc_key']).decode() == old_name:
                    inf['name_enc'] = base64.b64encode(encrypt_data(new_name.encode(), vault['keys']['enc_key'])).decode('ascii')
                    break
            except: pass
    save_mapping(vault['path'], m, vault['keys']['map_key'])
    return jsonify({'success': True})

def handle_download_file(data):
    tok = data.get('session'); fn = data.get('filename'); path = data.get('path', '/')
    if tok not in active_sessions: return jsonify({'success': False, 'error': 'Сессия истекла'})
    vault = active_sessions[tok]; vault['last_active'] = time.time()
    m = load_mapping(vault['path'], vault['keys']['map_key'])
    real_path = find_real_path(m, path, vault['keys']['enc_key'])
    if real_path not in m: return jsonify({'success': False, 'error': 'Путь не существует'})
    for fid, inf in m[real_path].get('files', {}).items():
        try:
            if decrypt_data(base64.b64decode(inf['name_enc']), vault['keys']['enc_key']).decode() == fn:
                ep = vault['path'] / inf['enc_path']
                if not ep.exists(): return jsonify({'success': False, 'error': 'Файл не найден'})
                if ep.stat().st_size > 50 * 1024 * 1024:
                    stream_token = secrets.token_hex(32)
                    preview_tokens[stream_token] = {'session': tok, 'path': path, 'name_enc': inf['name_enc'], 'created': time.time(), 'download': True}
                    return jsonify({'success': True, 'stream': True, 'token': stream_token, 'filename': fn, 'size': ep.stat().st_size})
                raw = ep.read_bytes(); nl = int.from_bytes(raw[:4], 'big')
                dec = decrypt_data(raw[4+nl:], vault['keys']['enc_key'])
                return jsonify({'success': True, 'data': base64.b64encode(dec).decode('ascii'), 'filename': fn})
        except: pass
    return jsonify({'success': False, 'error': 'Файл не найден'})

@app.route('/api/stream_file')
def stream_file():
    token = request.args.get('token')
    if not token or token not in preview_tokens: return 'Token invalid', 403
    info = preview_tokens.get(token)
    if not info or not info.get('download'): return 'Invalid token', 403
    if time.time() - info.get('created', 0) > 300: preview_tokens.pop(token, None); return 'Token expired', 403
    try:
        vault = active_sessions.get(info['session'])
        if not vault: return 'Session expired', 403
        keys = vault['keys']; mapping = load_mapping(vault['path'], keys['map_key'])
        real_path = find_real_path(mapping, info['path'], keys['enc_key'])
        if real_path not in mapping: return 'Path not found', 404
        for fid, finfo in mapping[real_path].get('files', {}).items():
            if finfo['name_enc'] == info['name_enc']:
                ep = vault['path'] / finfo['enc_path']
                if not ep.exists(): return 'File not found', 404
                def generate():
                    chunk_size = 1024 * 1024
                    with open(ep, 'rb') as f:
                        nl_bytes = f.read(4); nl = int.from_bytes(nl_bytes, 'big')
                        enc_name = f.read(nl); yield nl_bytes + enc_name
                        nonce = f.read(12); cipher = ChaCha20Poly1305(keys['enc_key']); buffer = nonce
                        while True:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                if len(buffer) > 12: yield cipher.decrypt(buffer[:12], buffer[12:], None)
                                break
                            buffer += chunk
                            while len(buffer) >= chunk_size + 12 + 16:
                                block = buffer[:chunk_size + 12 + 16]; buffer = buffer[chunk_size + 12 + 16:]
                                try: yield cipher.decrypt(block[:12], block[12:], None)
                                except: yield block
                orig_name = decrypt_data(base64.b64decode(finfo['name_enc']), keys['enc_key']).decode()
                return Response(generate(), mimetype='application/octet-stream', headers={'Content-Disposition': f'attachment; filename="{orig_name}"'})
    except Exception as e: logger.error(f"Stream error: {e}"); return 'Error', 500
    finally: preview_tokens.pop(token, None)
    return 'File not found', 404

def handle_get_blocking_mode(data):
    return jsonify({'success': True, 'block_browsers': load_blocking_mode()})

def handle_set_blocking_mode(data):
    enabled = data.get('enabled', True)
    save_blocking_mode(enabled)
    return jsonify({'success': True})

def handle_get_lock_timeout(data):
    return jsonify({'success': True, 'timeout': load_lock_timeout()})

def handle_set_lock_timeout(data):
    timeout = data.get('timeout', DEFAULT_INACTIVITY_LOCK)
    save_lock_timeout(timeout)
    return jsonify({'success': True})

def background_cleanup():
    while True: time.sleep(15); cleanup_sessions(); cleanup_tokens()

def start_flask():
    app.run(host='127.0.0.1', port=FLASK_PORT, debug=False, use_reloader=False)

class Api:
    def save_file_dialog(self, vault_id, session_token, path, filename):
        import tkinter as tk; from tkinter import filedialog
        root = tk.Tk(); root.withdraw()
        file_path = filedialog.asksaveasfilename(initialfile=filename, defaultextension=".*", filetypes=[("Все файлы", "*.*")])
        root.destroy()
        if file_path:
            tok = session_token
            if tok in active_sessions:
                vault = active_sessions[tok]
                m = load_mapping(vault['path'], vault['keys']['map_key'])
                real_path = find_real_path(m, path, vault['keys']['enc_key'])
                if real_path in m:
                    for fid, inf in m[real_path].get('files', {}).items():
                        try:
                            if decrypt_data(base64.b64decode(inf['name_enc']), vault['keys']['enc_key']).decode() == filename:
                                ep = vault['path'] / inf['enc_path']
                                if ep.exists():
                                    raw = ep.read_bytes(); nl = int.from_bytes(raw[:4], 'big')
                                    dec = decrypt_data(raw[4+nl:], vault['keys']['enc_key'])
                                    with open(file_path, 'wb') as f: f.write(dec)
                                break
                        except: pass
        return True

    def open_exe_file(self, vault_id, session_token, path, filename):
        import tempfile, subprocess, os as _os
        tok = session_token
        if tok in active_sessions:
            vault = active_sessions[tok]
            m = load_mapping(vault['path'], vault['keys']['map_key'])
            real_path = find_real_path(m, path, vault['keys']['enc_key'])
            if real_path in m:
                for fid, inf in m[real_path].get('files', {}).items():
                    try:
                        if decrypt_data(base64.b64decode(inf['name_enc']), vault['keys']['enc_key']).decode() == filename:
                            ep = vault['path'] / inf['enc_path']
                            if ep.exists():
                                raw = ep.read_bytes(); nl = int.from_bytes(raw[:4], 'big')
                                dec = decrypt_data(raw[4+nl:], vault['keys']['enc_key'])
                                tmpdir = tempfile.mkdtemp(prefix='EveryCrypt_')
                                tmppath = _os.path.join(tmpdir, filename)
                                with open(tmppath, 'wb') as f: f.write(dec)
                                if _os.name == 'nt': subprocess.Popen([tmppath], shell=True)
                                else: subprocess.Popen(['xdg-open', tmppath])
                            break
                    except: pass
        return True

def generate_self_signed_cert():
    """Генерирует самоподписанный сертификат для 127.0.0.1"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization as cert_serialization
    import ipaddress
    
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EveryCrypt"),
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow().replace(year=datetime.utcnow().year + 10)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]), critical=False,
    ).sign(private_key, crypto_hashes.SHA256(), default_backend())
    
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    with open(KEY_FILE, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=cert_serialization.Encoding.PEM,
            format=cert_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=cert_serialization.NoEncryption()
        ))
    with open(CERT_FILE, 'wb') as f:
        f.write(cert.public_bytes(cert_serialization.Encoding.PEM))
    
    logger.info("Самоподписанный сертификат создан")
    return True

def install_certificate():
    """Устанавливает самоподписанный сертификат в доверенные"""
    import subprocess
    import platform
    
    system = platform.system()
    
    if system == 'Windows':
        try:
            subprocess.run(['certutil', '-addstore', 'Root', str(CERT_FILE)], 
                         check=False, capture_output=True)
            logger.info("Сертификат установлен в Windows")
            return True
        except Exception as e:
            logger.warning(f"Не удалось установить сертификат: {e}")
    
    elif system == 'Darwin':
        try:
            subprocess.run(['sudo', 'security', 'add-trusted-cert', '-d', '-r', 'trustRoot',
                          '-k', '/Library/Keychains/System.keychain', str(CERT_FILE)], 
                         check=False, capture_output=True)
            logger.info("Сертификат установлен в macOS")
            return True
        except Exception as e:
            logger.warning(f"Не удалось установить сертификат: {e}")
    
    elif system == 'Linux':
        try:
            dest = '/usr/local/share/ca-certificates/everycrypt.crt'
            subprocess.run(['sudo', 'cp', str(CERT_FILE), dest], check=False)
            subprocess.run(['sudo', 'update-ca-certificates'], check=False)
            logger.info("Сертификат установлен в Linux")
            return True
        except Exception as e:
            logger.warning(f"Не удалось установить сертификат: {e}")
    
    return False

def main():
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        generate_self_signed_cert()
        install_certificate()
        CERT_INSTALLED_FLAG.touch()
    elif not CERT_INSTALLED_FLAG.exists():
        install_certificate()
        CERT_INSTALLED_FLAG.touch()
    
    logger.info("=" * 60)
    logger.info("EveryCrypt v2.1")
    logger.info(f"Директория: {CACHE_DIR}")
    logger.info(f"Защита MITM: {'ВКЛЮЧЕНА' if load_blocking_mode() else 'ОТКЛЮЧЕНА'}")
    logger.info("=" * 60)
    threading.Thread(target=start_flask, daemon=True).start()
    threading.Thread(target=background_cleanup, daemon=True).start()
    time.sleep(1.5)
    
    url_with_token = f'http://127.0.0.1:{FLASK_PORT}/?token={APP_SECRET_TOKEN}'
    
    api = Api()
    window = webview.create_window(
        title='EveryCrypt',
        url=url_with_token,
        js_api=api,
        width=1200, height=800,
        min_size=(800, 600),
        confirm_close=True,
        text_select=True,
    )
    
    webview.start(debug=False)
    
    for t in list(active_sessions.keys()):
        v = active_sessions.pop(t)
        if 'keys' in v:
            for k in v['keys'].values():
                if isinstance(k, bytearray): k[:] = b'\x00' * len(k)
    active_sessions.clear()
    preview_tokens.clear()
    thumbnail_tokens.clear()
    logger.info("EveryCrypt завершил работу")
if __name__ == '__main__':
    main()
