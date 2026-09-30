import os, json, uuid, hmac, hashlib, base64, re, copy, threading, contextvars, secrets, time, logging, atexit, smtplib, csv, io
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from email.message import EmailMessage
from pathlib import Path
import requests
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Request, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')
DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
DB = ROOT / 'data' / 'db.json'
DB.parent.mkdir(parents=True, exist_ok=True)

def env_int(name, default, minimum=None, maximum=None):
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


JWT_SECRET = os.getenv('JWT_SECRET', '').strip()
OWNER_USER = os.getenv('OWNER_USERNAME', 'owner').strip()
OWNER_PASS = os.getenv('OWNER_PASSWORD', '').strip()
COOKIE = 'estate_session'
CUSTOMER_COOKIE = 'estate_customer'
CHAT_COOKIE = 'estate_chat'
SESSION_DAYS = env_int('SESSION_DAYS', 30, 1, 3650)
MAX_UPLOAD_MB = env_int('MAX_UPLOAD_MB', 2, 1, 10)
CLOUDINARY_URL = os.getenv('CLOUDINARY_URL', '').strip()
MAX_PROPERTY_IMAGES = env_int('MAX_PROPERTY_IMAGES', 20, 1, 100)
MAX_IMAGE_BYTES = MAX_UPLOAD_MB * 1024 * 1024
DB_POOL_MAX_SIZE = env_int('DB_POOL_MAX_SIZE', 10, 2, 50)
RATE_LIMIT_PER_MINUTE = env_int('RATE_LIMIT_PER_MINUTE', 30, 1, 600)
SESSION_CACHE_TTL_SECONDS = env_int('SESSION_CACHE_TTL_SECONDS', 3600, 60, 86400)
AUTH_RATE_LIMIT_PER_MINUTE = env_int('AUTH_RATE_LIMIT_PER_MINUTE', 8, 1, 60)
MAX_QUERY_LENGTH = env_int('MAX_QUERY_LENGTH', 300, 20, 2000)
MAX_NOTES_LENGTH = env_int('MAX_NOTES_LENGTH', 2000, 100, 10000)
MAX_AUDIT_ITEMS = env_int('MAX_AUDIT_ITEMS', 5000, 100, 50000)
MAX_MESSAGE_HISTORY = env_int('MAX_MESSAGE_HISTORY', 8, 2, 20)
JWT_ISSUER = os.getenv('JWT_ISSUER', 'estateai').strip() or 'estateai'
JWT_AUDIENCE = os.getenv('JWT_AUDIENCE', 'estateai-web').strip() or 'estateai-web'
ENVIRONMENT = os.getenv('ENVIRONMENT', os.getenv('APP_ENV', 'development')).strip().lower()
SECURE_COOKIE = os.getenv('SECURE_COOKIE', 'true' if ENVIRONMENT == 'production' else 'false').lower() == 'true'
COOKIE_SAMESITE = os.getenv('COOKIE_SAMESITE', 'lax').lower()
if COOKIE_SAMESITE not in {'lax', 'strict', 'none'}:
    COOKIE_SAMESITE = 'lax'
if COOKIE_SAMESITE == 'none' and not SECURE_COOKIE:
    COOKIE_SAMESITE = 'lax'
SMTP_HOST = os.getenv('SMTP_HOST', '').strip()
SMTP_PORT = env_int('SMTP_PORT', 587, 1, 65535)
SMTP_USER = os.getenv('SMTP_USER', '').strip()
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USER).strip()
PUBLIC_BASE_URL = os.getenv('PUBLIC_BASE_URL', '').strip().rstrip('/')
REQUIRE_EMAIL_VERIFICATION = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'true').lower() == 'true'

_PG_CONN = contextvars.ContextVar('pg_conn', default=None)
_PG_POOL = None
_PG_POOL_LOCK = threading.Lock()
_DB_FILE_LOCK = threading.RLock()
_TOKEN_REVOKED = {}  # jti -> expiry timestamp
_TOKEN_REVOKED_LOCK = threading.Lock()
_LOG = logging.getLogger('estateai')

def _pg_url():
    return DATABASE_URL.replace('postgres://', 'postgresql://', 1) if DATABASE_URL else ''


def _pg_pool():
    global _PG_POOL
    if not DATABASE_URL:
        return None
    if _PG_POOL is None:
        with _PG_POOL_LOCK:
            if _PG_POOL is None:
                _PG_POOL = ConnectionPool(
                    conninfo=_pg_url(),
                    min_size=1,
                    max_size=DB_POOL_MAX_SIZE,
                    open=True,
                    timeout=10,
                    max_idle=300,
                    max_lifetime=1800,
                    check=ConnectionPool.check_connection,
                )
                try:
                    with _PG_POOL.connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("SET LOCAL lock_timeout = '5s'")
                            cur.execute("CREATE TABLE IF NOT EXISTS estate_state (id INTEGER PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
                        conn.commit()
                except Exception:
                    _PG_POOL.close()
                    _PG_POOL = None
                    raise
    return _PG_POOL


def _pg_request_conn():
    return _PG_CONN.get()



if not JWT_SECRET or len(JWT_SECRET) < 32 or len(set(JWT_SECRET)) < 8:
    raise RuntimeError('JWT_SECRET must be configured with at least 32 characters and sufficient entropy')
if not OWNER_PASS:
    raise RuntimeError('OWNER_PASSWORD must be configured before starting the application')
if not OWNER_PASS.startswith('$argon2') and len(OWNER_PASS) < 10:
    raise RuntimeError('OWNER_PASSWORD must be at least 10 characters long (or an Argon2 hash)')

ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
_SESSION_CACHE = {}
_SESSION_LOCK = threading.RLock()
_RATE_CACHE = {}
_RATE_LOCK = threading.Lock()

DEFAULT = {
    'settings': {
        'brand': 'EstateAI',
        'tagline': 'Find a place you will love to call home.',
        'owner_name': 'Property Owner',
        'owner_email': '',
        'phone': '',
        'whatsapp': '',
        'currency': '₹',
        'ai_greeting': 'Hi! I am your AI property advisor. Tell me your location, budget, property type or what you are looking for.',
        'business_hours': 'Mon-Sat 9:00 AM-7:00 PM',
        'about': 'A premium AI-powered real estate sales experience.',
        'address': '',
        'logo_url': '',
        'hero_image': '',
        'ai_business_context': 'You are a professional real-estate sales assistant with 20 years of experience. Be warm, concise and helpful. Use only published property data and public business settings. Never invent property facts, price, availability, location, owner details or legal claims. You may also give general real estate guidance on buying vs renting, home loans, registration process, vastu tips, and locality insights. Always reply in the same language the customer uses. Help customers search, compare, enquire and book site visits.'
    },
    'properties': [
        {'purpose': 'Buy', 'type': 'Apartment', 'price': 7200000, 'bhk': '2 BHK', 'bathrooms': '2', 'area': '1,120 sq ft', 'built_up_area': '', 'plot_area': '', 'floor': '', 'total_floors': '', 'location': 'Hinjewadi Phase 2, Pune, Maharashtra', 'locality': 'Hinjewadi', 'city': 'Pune', 'state': 'Maharashtra', 'pincode': '', 'map_url': 'https://maps.google.com/?q=Hinjewadi+Phase+2+Pune+Maharashtra', 'status': 'Ready to Move', 'facing': '', 'furnishing': '', 'parking': '', 'construction_year': '', 'rera': '', 'amenities': ['Clubhouse', 'Gym', 'Pool', 'Security', 'Power Backup'], 'description': 'Modern demo 2 BHK apartment for client presentation. Replace with verified property information before launch.', 'published': True, 'views': 24, 'is_demo': True, 'id': 'demo_p1', 'title': 'Skyline Residency — Demo Listing', 'images': [{'id': 'demo_img_1', 'name': 'demo-property.svg', 'url': '', 'data': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MDAgNDAwIj48ZGVmcz48bGluZWFyR3JhZGllbnQgaWQ9ImciIHgxPSIwIiB4Mj0iMSI+PHN0b3Agc3RvcC1jb2xvcj0iIzM2NWY0YiIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzEwMWYxOCIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPjxyZWN0IHdpZHRoPSI2MDAiIGhlaWdodD0iNDAwIiBmaWxsPSJ1cmwoI2cpIi8+PGNpcmNsZSBjeD0iNDkwIiBjeT0iNzAiIHI9IjQyIiBmaWxsPSIjZjVlN2IwIiBvcGFjaXR5PSIuOCIvPjxwYXRoIGQ9Ik0wIDM0NSBRMTQwIDI5NSAyODAgMzQwIFQ2MDAgMzI1IFY0MDAgSDBaIiBmaWxsPSIjMzE1NTQ1IiBvcGFjaXR5PSIuOSIvPjxyZWN0IHg9IjE2NSIgeT0iODAiIHdpZHRoPSIyNzAiIGhlaWdodD0iMzEwIiByeD0iMTAiIGZpbGw9IiNkZmU5ZTMiLz48ZyBmaWxsPSIjOGRhOTllIj48cmVjdCB4PSIxOTUiIHk9IjExNSIgd2lkdGg9IjU1IiBoZWlnaHQ9IjQ1Ii8+PHJlY3QgeD0iMjg1IiB5PSIxMTUiIHdpZHRoPSI1NSIgaGVpZ2h0PSI0NSIvPjxyZWN0IHg9IjM3NSIgeT0iMTE1IiB3aWR0aD0iMzUiIGhlaWdodD0iNDUiLz48cmVjdCB4PSIxOTUiIHk9IjE5MCIgd2lkdGg9IjU1IiBoZWlnaHQ9IjQ1Ii8+PHJlY3QgeD0iMjg1IiB5PSIxOTAiIHdpZHRoPSI1NSIgaGVpZ2h0PSI0NSIvPjxyZWN0IHg9IjM3NSIgeT0iMTkwIiB3aWR0aD0iMzUiIGhlaWdodD0iNDUiLz48cmVjdCB4PSIxOTUiIHk9IjI2NSIgd2lkdGg9IjU1IiBoZWlnaHQ9IjQ1Ii8+PHJlY3QgeD0iMjg1IiB5PSIyNjUiIHdpZHRoPSI1NSIgaGVpZ2h0PSI0NSIvPjxyZWN0IHg9IjM3NSIgeT0iMjY1IiB3aWR0aD0iMzUiIGhlaWdodD0iNDUiLz48L2c+PHJlY3QgeD0iMjc1IiB5PSIzMzAiIHdpZHRoPSI1MCIgaGVpZ2h0PSI2MCIgZmlsbD0iIzgyOWU4ZiIvPjx0ZXh0IHg9IjMwIiB5PSI0NSIgZmlsbD0id2hpdGUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIyMCIgZm9udC13ZWlnaHQ9IjcwMCI+REVNTyBMSVNUSU5HPC90ZXh0Pjx0ZXh0IHg9IjMwIiB5PSIzNzAiIGZpbGw9IndoaXRlIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMTciIGZvbnQtd2VpZ2h0PSI3MDAiPlNreWxpbmUgUmVzaWRlbmN5PC90ZXh0Pjx0ZXh0IHg9IjMwIiB5PSIzOTIiIGZpbGw9IiNkY2ViZTMiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxMiI+TW9kZXJuIDIgQkhLIOKAoiBQdW5lPC90ZXh0Pjwvc3ZnPg=='}]},
        {'purpose': 'Buy', 'type': 'Villa', 'price': 18500000, 'bhk': '4 BHK', 'bathrooms': '4', 'area': '2,850 sq ft', 'built_up_area': '', 'plot_area': '', 'floor': '', 'total_floors': '', 'location': 'Dona Paula, Panaji, Goa', 'locality': 'Dona Paula', 'city': 'Panaji', 'state': 'Goa', 'pincode': '', 'map_url': 'https://maps.google.com/?q=Dona+Paula+Panaji+Goa', 'status': 'Ready to Move', 'facing': '', 'furnishing': '', 'parking': '', 'construction_year': '', 'rera': '', 'amenities': ['Private Garden', 'Pool', 'Terrace', 'Security', 'Parking'], 'description': 'Premium demo villa for client presentation. Replace demo information with verified owner data before publishing.', 'published': True, 'views': 20, 'is_demo': True, 'id': 'demo_p2', 'title': 'Palm Grove Villa — Demo Listing', 'images': [{'id': 'demo_img_2', 'name': 'demo-property.svg', 'url': '', 'data': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MDAgNDAwIj48ZGVmcz48bGluZWFyR3JhZGllbnQgaWQ9ImciIHgxPSIwIiB4Mj0iMSI+PHN0b3Agc3RvcC1jb2xvcj0iIzVhNzI1YyIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzFiMzAyNSIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPjxyZWN0IHdpZHRoPSI2MDAiIGhlaWdodD0iNDAwIiBmaWxsPSJ1cmwoI2cpIi8+PGNpcmNsZSBjeD0iNDkwIiBjeT0iNzAiIHI9IjQyIiBmaWxsPSIjZjVlN2IwIiBvcGFjaXR5PSIuOCIvPjxwYXRoIGQ9Ik0wIDM0NSBRMTQwIDI5NSAyODAgMzQwIFQ2MDAgMzI1IFY0MDAgSDBaIiBmaWxsPSIjMzE1NTQ1IiBvcGFjaXR5PSIuOSIvPjxwYXRoIGQ9Ik0xNzAgMjMwIEwzMDAgMTIwIEw0MzAgMjMwIFYzOTAgSDE3MCBaIiBmaWxsPSIjZTllZmU5Ii8+PHBhdGggZD0iTTE0NSAyMzAgTDMwMCAxMDAgTDQ1NSAyMzAiIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxNCIvPjxyZWN0IHg9IjI1NSIgeT0iMjg1IiB3aWR0aD0iOTAiIGhlaWdodD0iMTA1IiBmaWxsPSIjN2Y5YzhjIi8+PHJlY3QgeD0iMTk1IiB5PSIyNTUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0NSIgZmlsbD0iI2I5ZDhjOCIvPjxyZWN0IHg9IjM1NyIgeT0iMjU1IiB3aWR0aD0iNDgiIGhlaWdodD0iNDUiIGZpbGw9IiNiOWQ4YzgiLz48dGV4dCB4PSIzMCIgeT0iNDUiIGZpbGw9IndoaXRlIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMjAiIGZvbnQtd2VpZ2h0PSI3MDAiPkRFTU8gTElTVElORzwvdGV4dD48dGV4dCB4PSIzMCIgeT0iMzcwIiBmaWxsPSJ3aGl0ZSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjE3IiBmb250LXdlaWdodD0iNzAwIj5QYWxtIEdyb3ZlIFZpbGxhPC90ZXh0Pjx0ZXh0IHg9IjMwIiB5PSIzOTIiIGZpbGw9IiNkY2ViZTMiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxMiI+THV4dXJ5IDQgQkhLIOKAoiBHb2E8L3RleHQ+PC9zdmc+'}]},
        {'purpose': 'Rent', 'type': 'House', 'price': 55000, 'bhk': '3 BHK', 'bathrooms': '3', 'area': '1,980 sq ft', 'built_up_area': '', 'plot_area': '', 'floor': '', 'total_floors': '', 'location': 'Whitefield, Bengaluru, Karnataka', 'locality': 'Whitefield', 'city': 'Bengaluru', 'state': 'Karnataka', 'pincode': '', 'map_url': 'https://maps.google.com/?q=Whitefield+Bengaluru+Karnataka', 'status': 'Ready to Move', 'facing': '', 'furnishing': '', 'parking': '', 'construction_year': '', 'rera': '', 'amenities': ['Gated Community', 'Garden', 'Security', 'Water Supply', 'Parking'], 'description': 'Demo rental home for presentation. Replace all facts with verified listing information before launch.', 'published': True, 'views': 16, 'is_demo': True, 'id': 'demo_p3', 'title': 'Maple Family Home — Demo Listing', 'images': [{'id': 'demo_img_3', 'name': 'demo-property.svg', 'url': '', 'data': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MDAgNDAwIj48ZGVmcz48bGluZWFyR3JhZGllbnQgaWQ9ImciIHgxPSIwIiB4Mj0iMSI+PHN0b3Agc3RvcC1jb2xvcj0iIzdhNmI1OSIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzJkM2IzMCIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPjxyZWN0IHdpZHRoPSI2MDAiIGhlaWdodD0iNDAwIiBmaWxsPSJ1cmwoI2cpIi8+PGNpcmNsZSBjeD0iNDkwIiBjeT0iNzAiIHI9IjQyIiBmaWxsPSIjZjVlN2IwIiBvcGFjaXR5PSIuOCIvPjxwYXRoIGQ9Ik0wIDM0NSBRMTQwIDI5NSAyODAgMzQwIFQ2MDAgMzI1IFY0MDAgSDBaIiBmaWxsPSIjMzE1NTQ1IiBvcGFjaXR5PSIuOSIvPjxwYXRoIGQ9Ik0xNTAgMjI1IEwzMDAgMTA1IEw0NTAgMjI1IFYzOTAgSDE1MCBaIiBmaWxsPSIjZjBlN2Q3Ii8+PHBhdGggZD0iTTEzMCAyMjUgTDMwMCA5MCBMNDcwIDIyNSIgZmlsbD0iI2I2N2I1NSIvPjxyZWN0IHg9IjI2NSIgeT0iMjkwIiB3aWR0aD0iNzAiIGhlaWdodD0iMTAwIiBmaWxsPSIjN2U5YzhiIi8+PHJlY3QgeD0iMTg1IiB5PSIyNjAiIHdpZHRoPSI1MCIgaGVpZ2h0PSI0OCIgZmlsbD0iIzkxYjVhYSIvPjxyZWN0IHg9IjM2NSIgeT0iMjYwIiB3aWR0aD0iNTAiIGhlaWdodD0iNDgiIGZpbGw9IiM5MWI1YWEiLz48dGV4dCB4PSIzMCIgeT0iNDUiIGZpbGw9IndoaXRlIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMjAiIGZvbnQtd2VpZ2h0PSI3MDAiPkRFTU8gTElTVElORzwvdGV4dD48dGV4dCB4PSIzMCIgeT0iMzcwIiBmaWxsPSJ3aGl0ZSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjE3IiBmb250LXdlaWdodD0iNzAwIj5NYXBsZSBGYW1pbHkgSG9tZTwvdGV4dD48dGV4dCB4PSIzMCIgeT0iMzkyIiBmaWxsPSIjZGNlYmUzIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMTIiPlNwYWNpb3VzIDMgQkhLIOKAoiBCZW5nYWx1cnU8L3RleHQ+PC9zdmc+'}]},
        {'purpose': 'Buy', 'type': 'Plot', 'price': 4200000, 'bhk': '', 'bathrooms': '', 'area': '2,400 sq ft', 'built_up_area': '', 'plot_area': '', 'floor': '', 'total_floors': '', 'location': 'Trimbak Road, Nashik, Maharashtra', 'locality': 'Trimbak Road', 'city': 'Nashik', 'state': 'Maharashtra', 'pincode': '', 'map_url': 'https://maps.google.com/?q=Trimbak+Road+Nashik+Maharashtra', 'status': 'Ready to Move', 'facing': '', 'furnishing': '', 'parking': '', 'construction_year': '', 'rera': '', 'amenities': ['Road Access', 'Electricity Nearby', 'Water Nearby'], 'description': 'Demo plot listing. Verify title, zoning, ownership and approvals before any real transaction.', 'published': True, 'views': 12, 'is_demo': True, 'id': 'demo_p4', 'title': 'Greenfield Plot — Demo Listing', 'images': [{'id': 'demo_img_4', 'name': 'demo-property.svg', 'url': '', 'data': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MDAgNDAwIj48ZGVmcz48bGluZWFyR3JhZGllbnQgaWQ9ImciIHgxPSIwIiB4Mj0iMSI+PHN0b3Agc3RvcC1jb2xvcj0iIzRmNzQ0ZiIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzE1MjIxOCIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPjxyZWN0IHdpZHRoPSI2MDAiIGhlaWdodD0iNDAwIiBmaWxsPSJ1cmwoI2cpIi8+PGNpcmNsZSBjeD0iNDkwIiBjeT0iNzAiIHI9IjQyIiBmaWxsPSIjZjVlN2IwIiBvcGFjaXR5PSIuOCIvPjxwYXRoIGQ9Ik0wIDM0NSBRMTQwIDI5NSAyODAgMzQwIFQ2MDAgMzI1IFY0MDAgSDBaIiBmaWxsPSIjMzE1NTQ1IiBvcGFjaXR5PSIuOSIvPjxwb2x5Z29uIHBvaW50cz0iMTQ1LDM0MCAyMzAsMTY1IDQyNSwxODUgNDcwLDM0NSIgZmlsbD0iIzlkYmI4MiIvPjxwYXRoIGQ9Ik0xNDUgMzQwIEwyMzAgMTY1IEw0MjUgMTg1IEw0NzAgMzQ1IFoiIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2YyZjZlZSIgc3Ryb2tlLXdpZHRoPSI4Ii8+PGNpcmNsZSBjeD0iMjEwIiBjeT0iMjQ1IiByPSIyNSIgZmlsbD0iIzU0NzQ1MSIvPjxjaXJjbGUgY3g9IjQwNSIgY3k9IjI2NSIgcj0iMzAiIGZpbGw9IiM1NDc0NTEiLz48dGV4dCB4PSIzMCIgeT0iNDUiIGZpbGw9IndoaXRlIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMjAiIGZvbnQtd2VpZ2h0PSI3MDAiPkRFTU8gTElTVElORzwvdGV4dD48dGV4dCB4PSIzMCIgeT0iMzcwIiBmaWxsPSJ3aGl0ZSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjE3IiBmb250LXdlaWdodD0iNzAwIj5HcmVlbmZpZWxkIFBsb3Q8L3RleHQ+PHRleHQgeD0iMzAiIHk9IjM5MiIgZmlsbD0iI2RjZWJlMyIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjEyIj5SZXNpZGVudGlhbCBwbG90IOKAoiBOYXNoaWs8L3RleHQ+PC9zdmc+'}]},
{'purpose': 'Commercial', 'type': 'Commercial', 'price': 9500000, 'bhk': '', 'bathrooms': '2', 'area': '1,650 sq ft', 'built_up_area': '', 'plot_area': '', 'floor': '', 'total_floors': '', 'location': 'Andheri East, Mumbai, Maharashtra', 'locality': 'Andheri East', 'city': 'Mumbai', 'state': 'Maharashtra', 'pincode': '', 'map_url': 'https://maps.google.com/?q=Andheri+East+Mumbai+Maharashtra', 'status': 'Ready to Move', 'facing': '', 'furnishing': '', 'parking': '', 'construction_year': '', 'rera': '', 'amenities': ['Lift', 'Reception', 'Security', 'Parking', 'Power Backup'], 'description': 'Demo commercial listing for client presentation. Replace all facts with verified commercial property information before launch.', 'published': True, 'views': 8, 'is_demo': True, 'id': 'demo_p5', 'title': 'Central Business Hub — Demo Listing', 'images': [{'id': 'demo_img_5', 'name': 'demo-property.svg', 'url': '', 'data': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MDAgNDAwIj48ZGVmcz48bGluZWFyR3JhZGllbnQgaWQ9ImciIHgxPSIwIiB4Mj0iMSI+PHN0b3Agc3RvcC1jb2xvcj0iIzRiNjY3MCIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzE1MWUyNSIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPjxyZWN0IHdpZHRoPSI2MDAiIGhlaWdodD0iNDAwIiBmaWxsPSJ1cmwoI2cpIi8+PGNpcmNsZSBjeD0iNDkwIiBjeT0iNzAiIHI9IjQyIiBmaWxsPSIjZjVlN2IwIiBvcGFjaXR5PSIuOCIvPjxwYXRoIGQ9Ik0wIDM0NSBRMTQwIDI5NSAyODAgMzQwIFQ2MDAgMzI1IFY0MDAgSDBaIiBmaWxsPSIjMzE1NTQ1IiBvcGFjaXR5PSIuOSIvPjxyZWN0IHg9IjEyNSIgeT0iMTQ1IiB3aWR0aD0iMzUwIiBoZWlnaHQ9IjIyMCIgcng9IjEwIiBmaWxsPSIjZDllNWRmIi8+PHJlY3QgeD0iMTU1IiB5PSIxODAiIHdpZHRoPSI5MCIgaGVpZ2h0PSIxNTAiIGZpbGw9IiM5YWI1YWEiLz48cmVjdCB4PSIyNzAiIHk9IjE4MCIgd2lkdGg9IjkwIiBoZWlnaHQ9IjE1MCIgZmlsbD0iIzhkYTk5ZSIvPjxyZWN0IHg9IjM4NSIgeT0iMTgwIiB3aWR0aD0iNjAiIGhlaWdodD0iMTUwIiBmaWxsPSIjNzc5ODhiIi8+PHRleHQgeD0iMzAiIHk9IjQ1IiBmaWxsPSJ3aGl0ZSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjIwIiBmb250LXdlaWdodD0iNzAwIj5ERU1PIExJU1RJTkc8L3RleHQ+PHRleHQgeD0iMzAiIHk9IjM3MCIgZmlsbD0id2hpdGUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxNyIgZm9udC13ZWlnaHQ9IjcwMCI+Q2VudHJhbCBCdXNpbmVzcyBIdWI8L3RleHQ+PHRleHQgeD0iMzAiIHk9IjM5MiIgZmlsbD0iI2RjZWJlMyIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjEyIj5Db21tZXJjaWFsIHNwYWNlIOKAoiBNdW1iYWk8L3RleHQ+PC9zdmc+'}]}
    ],
    'customers': [],
    'leads': [],
    'visits': [],
    'messages': [],
    'notifications': [],
    'audit': [],
    'metrics': {'searches': 0, 'calls': 0, 'whatsapp': 0, 'bookings': 0, 'enquiries': 0, 'property_views': 0, 'chat_sessions': 0},
    'next': 1
}


def _merge_defaults(d):
    for k, v in DEFAULT.items():
        if k not in d:
            d[k] = copy.deepcopy(v)
    return d


def load():
    conn = _pg_request_conn()
    if DATABASE_URL:
        if conn is None:
            pool = _pg_pool()
            with pool.connection() as local_conn:
                return _load_pg(local_conn)
        return _load_pg(conn)

    with _DB_FILE_LOCK:
        if not DB.exists():
            _atomic_json_save(copy.deepcopy(DEFAULT))
        try:
            raw = DB.read_text(encoding='utf-8')
            d = json.loads(raw)
            if not isinstance(d, dict):
                raise ValueError('Database root must be an object')
            return _merge_defaults(d)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            _LOG.error('Local database read failed: %s', exc)
            raise RuntimeError('Local database is unreadable; restore a valid backup before continuing')


def _load_pg(conn):
    with conn.cursor() as cur:
        cur.execute('SELECT data FROM estate_state WHERE id=1')
        row = cur.fetchone()
        if row is None:
            d = copy.deepcopy(DEFAULT)
            cur.execute('INSERT INTO estate_state (id, data) VALUES (1, %s)', (json.dumps(d, ensure_ascii=False),))
            return d
        d = row[0]
        if not isinstance(d, dict):
            raise RuntimeError('Stored database state is invalid')
        return _merge_defaults(d)


def save(d):
    d = _merge_defaults(d)
    if DATABASE_URL:
        conn = _pg_request_conn()
        if conn is None:
            pool = _pg_pool()
            with pool.connection() as local_conn:
                _save_pg(local_conn, d)
                local_conn.commit()
        else:
            _save_pg(conn, d)
        return

    with _DB_FILE_LOCK:
        _atomic_json_save(d)


def _save_pg(conn, d):
    payload = json.dumps(d, ensure_ascii=False)
    with conn.cursor() as cur:
        cur.execute(
            '''INSERT INTO estate_state (id, data, updated_at)
               VALUES (1, %s, NOW())
               ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()''',
            (payload,)
        )


def _atomic_json_save(d):
    tmp = DB.with_name(DB.name + '.' + uuid.uuid4().hex + '.tmp')
    payload = json.dumps(d, ensure_ascii=False, indent=2).encode('utf-8')
    with open(tmp, 'wb') as fh:
        fh.write(payload); fh.flush(); os.fsync(fh.fileno())
    os.replace(tmp, DB)
    try:
        fd = os.open(str(DB.parent), os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    except (AttributeError, OSError):
        pass


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        if password_hash.startswith('$argon2'):
            return ph.verify(password_hash, password)
        if re.fullmatch(r'[0-9a-f]{64}', password_hash or ''):
            return hmac.compare_digest(password_hash, hashlib.sha256(password.encode()).hexdigest())
        return False
    except Exception:
        return False


def _cleanup_revoked_locked(now_ts=None):
    now_ts = now_ts or time.time()
    expired = [jti for jti, exp in _TOKEN_REVOKED.items() if exp <= now_ts]
    for jti in expired:
        _TOKEN_REVOKED.pop(jti, None)
    # Never evict an unexpired revocation: doing so can make a logged-out token valid again.
    # Expired entries are removed above, so the map naturally follows token lifetime.


def _token_is_revoked(jti):
    now_ts = time.time()
    with _TOKEN_REVOKED_LOCK:
        _cleanup_revoked_locked(now_ts)
        return jti in _TOKEN_REVOKED


def revoke_token(token):
    try:
        body, _ = token.split('.', 1)
        p = json.loads(base64.urlsafe_b64decode(body + '==='))
        jti = p.get('jti')
        exp = int(p.get('exp', 0) or 0)
        if jti and exp > int(time.time()):
            with _TOKEN_REVOKED_LOCK:
                _cleanup_revoked_locked()
                _TOKEN_REVOKED[jti] = exp
                _cleanup_revoked_locked()
    except Exception:
        return


def get_session_history(d, session_id, limit=MAX_MESSAGE_HISTORY):
    now_ts = time.time()
    limit = max(2, min(int(limit), MAX_MESSAGE_HISTORY))
    with _SESSION_LOCK:
        cached = _SESSION_CACHE.get(session_id)
        if cached is not None:
            ts, items = cached
            if now_ts - ts <= SESSION_CACHE_TTL_SECONDS:
                _SESSION_CACHE[session_id] = (now_ts, items)
                return items[-limit:]
            _SESSION_CACHE.pop(session_id, None)
    hist = [m for m in d['messages'] if m.get('session_id') == session_id][-limit:]
    with _SESSION_LOCK:
        _SESSION_CACHE[session_id] = (now_ts, hist[-20:])
    return hist[-limit:]


def append_session_message(session_id, item):
    with _SESSION_LOCK:
        now_ts = time.time()
        cached = _SESSION_CACHE.get(session_id)
        hist = list(cached[1]) if cached and now_ts - cached[0] <= SESSION_CACHE_TTL_SECONDS else []
        hist.append(item)
        _SESSION_CACHE[session_id] = (now_ts, hist[-20:])
        if len(_SESSION_CACHE) > 5000:
            oldest = sorted(_SESSION_CACHE.items(), key=lambda kv: kv[1][0])[:1000]
            for key, _ in oldest:
                _SESSION_CACHE.pop(key, None)


def now():
    return datetime.now(timezone.utc).isoformat()


def uid(prefix=''):
    return prefix + str(uuid.uuid4())


def audit(d, action, meta=None):
    d['audit'].insert(0, {'id': uid('a_'), 'at': now(), 'action': action, 'meta': meta or {}})
    if len(d['audit']) > MAX_AUDIT_ITEMS:
        del d['audit'][MAX_AUDIT_ITEMS:]


def public_props(d):
    out = []
    for p in d.get('properties', []):
        if not p.get('deleted_at') and p.get('published') and p.get('status', '') not in ['Draft', 'Archived']:
            item = copy.deepcopy(p)
            item.pop('is_demo', None)
            out.append(item)
    return out


def normalize_phone(v):
    return re.sub(r'[^0-9+]', '', v or '')


def valid_phone(v):
    n = re.sub(r'\D', '', v or '')
    return 7 <= len(n) <= 15


def whatsapp_url(v):
    n = normalize_phone(v).replace('+', '')
    return 'https://wa.me/' + n if n else ''


def make_token(user, role, days=1, session_version=None):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    payload = {
        'u': user,
        'role': role,
        'iat': now_ts,
        'nbf': now_ts - 5,
        'exp': now_ts + days * 86400,
        'jti': secrets.token_urlsafe(18),
        'iss': JWT_ISSUER,
        'aud': JWT_AUDIENCE,
    }
    if role == 'customer':
        payload['sv'] = int(session_version or 1)
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
    sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return body + '.' + base64.urlsafe_b64encode(sig).decode().rstrip('=')


def verify(t, role=None):
    try:
        body, encoded_sig = t.split('.', 1)
        if len(body) > 4096 or len(encoded_sig) > 4096:
            return None
        sig = base64.urlsafe_b64decode(encoded_sig + '===')
        good = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good):
            return None
        p = json.loads(base64.urlsafe_b64decode(body + '==='))
        now_ts = int(datetime.now(timezone.utc).timestamp())
        if p.get('iss') != JWT_ISSUER or p.get('aud') != JWT_AUDIENCE:
            return None
        if p.get('nbf', 0) > now_ts + 30 or p.get('exp', 0) <= now_ts - 30:
            return None
        if role and p.get('role') != role:
            return None
        if not p.get('u') or not p.get('jti') or _token_is_revoked(p['jti']):
            return None
        if p.get('role') == 'customer':
            # Password changes/resets increment the account session version,
            # invalidating every previously issued customer token.
            d = load()
            c = next((z for z in d.get('customers', []) if z.get('id') == p.get('u') and not z.get('deleted_at')), None)
            if not c or int(p.get('sv', 1)) != int(c.get('session_version', 1) or 1):
                return None
        return p
    except Exception:
        return None


def owner(request: Request):
    p = verify(request.cookies.get(COOKIE, ''), 'owner')
    if not p:
        raise HTTPException(401, 'Owner login required')
    return p


def customer(request: Request):
    p = verify(request.cookies.get(CUSTOMER_COOKIE, ''), 'customer')
    if not p:
        raise HTTPException(401, 'Customer login required')
    return p


def optional_customer(request: Request):
    return verify(request.cookies.get(CUSTOMER_COOKIE, ''), 'customer')


def chat_session(request: Request, requested: str = '', customer_id: str = '', d=None):
    token = request.cookies.get(CHAT_COOKIE, '')
    valid_token = bool(token and re.fullmatch(r's_[A-Za-z0-9_-]{20,100}', token))
    if requested and re.fullmatch(r's_[A-Za-z0-9_-]{20,100}', requested):
        # A client may reuse only its own chat cookie. Authenticated customers may
        # additionally resume a session that is already linked to their account.
        if valid_token and requested == token:
            return requested, False
        if customer_id and d is not None:
            owners = {m.get('customer_id') for m in d.get('messages', []) if m.get('session_id') == requested}
            if owners and owners <= {customer_id}:
                return requested, not valid_token
        requested = ''
    if valid_token:
        return token, False
    sid = 's_' + uuid.uuid4().hex
    return sid, True


def groq(messages, model=None, image_data=None):
    key = os.getenv('GROQ_API_KEY', '').strip()
    if not key:
        return None
    model = model or os.getenv('GROQ_TEXT_MODEL', 'openai/gpt-oss-120b')
    timeout = env_int('GROQ_TIMEOUT_SECONDS', 30, 5, 60)
    retries = env_int('GROQ_RETRIES', 2, 0, 3)
    if image_data:
        messages = [dict(m) for m in messages]
        last = messages[-1]
        content = [
            {'type': 'text', 'text': last.get('content', '')[:4000]},
            {'type': 'image_url', 'image_url': {'url': image_data}},
        ]
        messages[-1] = {**last, 'content': content}
    payload = {
        'model': model,
        'messages': messages,
        'temperature': float(os.getenv('GROQ_TEMPERATURE', '0.25')),
        'max_completion_tokens': env_int('GROQ_MAX_TOKENS', 1200, 128, 3000),
    }
    for attempt in range(retries + 1):
        try:
            r = requests.post(
                'https://api.groq.com/openai/v1/chat/completions',
                headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'},
                json=payload,
                timeout=timeout,
            )
            if r.ok:
                data = r.json()
                answer = data.get('choices', [{}])[0].get('message', {}).get('content', '')
                if isinstance(answer, str) and answer.strip():
                    return answer.strip()[:12000]
            if r.status_code not in {408, 429, 500, 502, 503, 504}:
                break
        except (requests.RequestException, ValueError, KeyError, IndexError) as exc:
            _LOG.warning('Groq request failed (attempt %s): %s', attempt + 1, exc)
        if attempt < retries:
            time.sleep(0.4 * (2 ** attempt))
    return None


def _shutdown_pool():
    global _PG_POOL
    if _PG_POOL is not None:
        try:
            _PG_POOL.close()
        except Exception:
            pass
        _PG_POOL = None


@asynccontextmanager
async def lifespan(app):
    try:
        d = load()
        changed = False
        for c in d.get('customers', []):
            if 'email_verified' not in c:
                c['email_verified'] = True
                c['updated_at'] = c.get('updated_at') or now()
                changed = True
            if 'session_version' not in c:
                c['session_version'] = 1
                c['updated_at'] = c.get('updated_at') or now()
                changed = True
        if changed:
            save(d)
            _LOG.info('Migrated legacy customer authentication fields')
    except Exception:
        _LOG.exception('Legacy customer migration failed')
    yield
    _shutdown_pool()


app = FastAPI(title='EstateAI - Premium AI Real Estate Sales Platform', version='4.1.0', lifespan=lifespan)
atexit.register(_shutdown_pool)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    _LOG.exception('Unhandled application error on %s %s', request.method, request.url.path)
    return JSONResponse({'detail': 'Internal server error'}, status_code=500)


@app.middleware('http')
async def persistence_middleware(request: Request, call_next):
    if request.method in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'} and request.url.path.startswith('/api/'):
        forwarded = request.headers.get('x-forwarded-for', '').strip()
        # Only trust forwarded address when an explicit trusted proxy list is configured.
        trusted_proxies = {x.strip() for x in os.getenv('TRUSTED_PROXY_IPS', '').split(',') if x.strip()}
        client_ip = request.client.host if request.client else 'unknown'
        if client_ip in trusted_proxies and forwarded:
            key = forwarded.split(',')[0].strip()
        else:
            key = client_ip

        bucket_prefix = 'auth:' if request.url.path in {'/api/auth/login', '/api/customer/login', '/api/customer/signup'} else 'api:'
        bucket = bucket_prefix + request.method + ':' + request.url.path + ':' + key
        limit = 5 if request.method == 'POST' and re.fullmatch(r'/api/properties/[^/]+/images', request.url.path) else (AUTH_RATE_LIMIT_PER_MINUTE if bucket_prefix == 'auth:' else RATE_LIMIT_PER_MINUTE)
        now_ts = time.time()
        with _RATE_LOCK:
            recent = [t for t in _RATE_CACHE.get(bucket, []) if now_ts - t < 60]
            if len(recent) >= limit:
                return JSONResponse({'detail': 'Too many requests. Please try again shortly.'}, status_code=429, headers={'Retry-After': '60'})
            recent.append(now_ts)
            _RATE_CACHE[bucket] = recent
            if len(_RATE_CACHE) > 10000:
                stale = [k for k, vals in _RATE_CACHE.items() if not vals or now_ts - vals[-1] > 300]
                for k in stale[:5000]:
                    _RATE_CACHE.pop(k, None)

        # Same-origin protection for browser state-changing requests.
        origin = request.headers.get('origin')
        if origin:
            allowed = set(ALLOWED_ORIGINS)
            host_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if allowed and origin not in allowed:
                return JSONResponse({'detail': 'Origin not allowed'}, status_code=403)
            if not allowed and origin != host_origin:
                return JSONResponse({'detail': 'Cross-site request blocked'}, status_code=403)

    if not DATABASE_URL or request.method in {'GET', 'HEAD', 'OPTIONS'}:
        response = await call_next(request)
    else:
        pool = _pg_pool()
        with pool.connection() as conn:
            token = _PG_CONN.set(conn)
            try:
                with conn.cursor() as cur:
                    cur.execute("SET LOCAL lock_timeout = '5s'")
                    cur.execute('SELECT pg_advisory_xact_lock(73421901)')
                response = await call_next(request)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                _PG_CONN.reset(token)

    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    response.headers.setdefault('Cache-Control', 'no-store' if request.url.path.startswith('/api/') else 'public, max-age=300')
    if request.url.scheme == 'https' or SECURE_COOKIE:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response


# TRUSTED_PROXY_IPS: comma-separated reverse-proxy IPs allowed to supply X-Forwarded-For.
ALLOWED_ORIGINS = [o.strip() for o in os.getenv('ALLOWED_ORIGINS', '').split(',') if o.strip()]
if ALLOWED_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allow_headers=['Content-Type','Accept'], allow_credentials=True)


def valid_http_url(v):
    if not v:
        return True
    return bool(re.fullmatch(r'https?://[^\s<>"\']{1,950}', v, re.IGNORECASE))


def validate_image_bytes(content_type, raw):
    if not raw:
        return False
    if content_type == 'image/jpeg':
        return raw[:3] == b'\xff\xd8\xff'
    if content_type == 'image/png':
        return raw[:8] == b'\x89PNG\r\n\x1a\n'
    if content_type == 'image/webp':
        return raw[:4] == b'RIFF' and raw[8:12] == b'WEBP'
    return False


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=128)
    remember: bool = False


class CustomerSignup(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    phone: str = Field(min_length=7, max_length=20)
    password: str = Field(min_length=10, max_length=128)

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        v = v.strip().lower()
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', v):
            raise ValueError('Invalid email address')
        return v


class CustomerLogin(BaseModel):
    email: str
    password: str = Field(min_length=1, max_length=128)


class Chat(BaseModel):
    message: str = Field(default='', max_length=4000)
    session_id: str = ''
    property_id: str = ''
    image_data: str = Field(default='', max_length=2_800_000)

    @field_validator('message')
    @classmethod
    def validate_message(cls, v):
        return v.strip()

    @field_validator('session_id')
    @classmethod
    def validate_session_id(cls, v):
        return v if re.fullmatch(r's_[A-Za-z0-9_-]{20,100}', v or '') else ''

    @field_validator('image_data')
    @classmethod
    def validate_image_data(cls, v):
        if not v:
            return ''
        if not re.fullmatch(r'data:image/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=\s]+', v):
            raise ValueError('Invalid image data')
        compact = v.replace('\n', '').replace('\r', '')
        media_type = compact.split(';', 1)[0].split(':', 1)[1]
        try:
            decoded = base64.b64decode(compact.split(',', 1)[1], validate=True)
        except Exception as exc:
            raise ValueError('Invalid base64 image data') from exc
        if len(decoded) > MAX_IMAGE_BYTES:
            raise ValueError(f'Chat image exceeds the {MAX_UPLOAD_MB} MB limit')
        if not validate_image_bytes(media_type, decoded):
            raise ValueError('Invalid or corrupted image file')
        return compact


class Lead(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=7, max_length=20)
    email: str = Field(default='', max_length=254)
    budget: str = Field(default='', max_length=100)
    location: str = Field(default='', max_length=200)
    bhk: str = Field(default='', max_length=30)
    property_id: str = Field(default='', max_length=100)
    source: str = Field(default='Website', max_length=50)
    consent: bool = False
    customer_id: str = ''

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        v = v.strip().lower()
        if v and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', v):
            raise ValueError('Invalid email address')
        return v

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if not valid_phone(v):
            raise ValueError('Invalid phone number')
        return normalize_phone(v)

class Visit(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=7, max_length=20)
    email: str = Field(default='', max_length=254)
    date: str
    time: str
    property_id: str = Field(default='', max_length=100)
    notes: str = Field(default='', max_length=2000)
    consent: bool = False
    customer_id: str = ''

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        v = v.strip().lower()
        if v and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', v):
            raise ValueError('Invalid email address')
        return v

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if not valid_phone(v):
            raise ValueError('Invalid phone number')
        return normalize_phone(v)

    @field_validator('date')
    @classmethod
    def validate_date(cls, v):
        try:
            d = datetime.strptime(v, '%Y-%m-%d').date()
        except ValueError:
            raise ValueError('Date must be YYYY-MM-DD')
        if d < datetime.now().astimezone().date():
            raise ValueError('Date cannot be in the past')
        return v

    @field_validator('time')
    @classmethod
    def validate_time(cls, v):
        try:
            datetime.strptime(v, '%H:%M')
        except ValueError:
            raise ValueError('Time must be HH:MM')
        return v


class Settings(BaseModel):
    brand: str = Field(default='EstateAI', max_length=100)
    tagline: str = Field(default='', max_length=300)
    owner_name: str = Field(default='', max_length=120)
    owner_email: str = Field(default='', max_length=254)
    phone: str = Field(default='', max_length=30)
    whatsapp: str = Field(default='', max_length=30)
    currency: str = Field(default='₹', max_length=5)
    ai_greeting: str = Field(default='', max_length=500)
    business_hours: str = Field(default='', max_length=200)
    about: str = Field(default='', max_length=3000)
    address: str = Field(default='', max_length=500)
    logo_url: str = Field(default='', max_length=1000)
    hero_image: str = Field(default='', max_length=1000)
    ai_business_context: str = Field(default='', max_length=5000)

    @field_validator('owner_email')
    @classmethod
    def validate_owner_email(cls, v):
        v = v.strip().lower()
        if v and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', v):
            raise ValueError('Invalid email address')
        return v

    @field_validator('logo_url', 'hero_image')
    @classmethod
    def validate_urls(cls, v):
        v = v.strip()
        if v and not valid_http_url(v):
            raise ValueError('URL must be a valid http(s) URL')
        return v


class StatusUpdate(BaseModel):
    status: str

    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        allowed = {
            'New', 'Contacted', 'Visit Scheduled', 'Negotiation', 'Closed', 'Lost', 'Qualified', 'Won',
            'Pending', 'Confirmed', 'Rescheduled', 'Completed', 'Cancelled'
        }
        if v not in allowed:
            raise ValueError('Invalid status')
        return v


class CustomerProfile(BaseModel):
    name: str
    phone: str = Field(default='', max_length=30)
    email: str = ''


@app.get('/')
def home(request: Request):
    path=ROOT/'index.html'; stat=path.stat(); etag='"'+hashlib.sha256(f'{stat.st_mtime_ns}:{stat.st_size}'.encode()).hexdigest()+'"'
    if request.headers.get('if-none-match')==etag: return Response(status_code=304,headers={'ETag':etag,'Cache-Control':'public, max-age=60'})
    return FileResponse(path,headers={'ETag':etag,'Cache-Control':'public, max-age=60, must-revalidate'})


@app.get('/api/health')
def health():
    db_ok = True
    try:
        if DATABASE_URL:
            pool = _pg_pool()
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT 1')
                    cur.fetchone()
        else:
            if not DB.exists():
                _atomic_json_save(copy.deepcopy(DEFAULT))
            json.loads(DB.read_text(encoding='utf-8'))
    except Exception:
        db_ok = False
    return {
        'ok': db_ok,
        'time': now(),
        'storage': 'postgresql' if DATABASE_URL else 'local-json',
        'image_storage': 'cloudinary' if CLOUDINARY_URL else 'local-fallback',
    }


# ---------- Auth ----------
@app.post('/api/auth/login')
def owner_login(x: Login, request: Request):
    password_ok = False
    if x.username == OWNER_USER:
        if OWNER_PASS.startswith('$argon2'):
            try:
                password_ok = ph.verify(OWNER_PASS, x.password)
            except Exception:
                password_ok = False
        else:
            password_ok = hmac.compare_digest(x.password, OWNER_PASS)
    if not password_ok:
        raise HTTPException(401, 'Invalid owner username or password')
    t = make_token(x.username, 'owner', SESSION_DAYS if x.remember else 1)
    r = JSONResponse({'ok': True, 'role': 'owner', 'username': x.username})
    r.set_cookie(COOKIE, t, max_age=SESSION_DAYS * 86400 if x.remember else None, httponly=True, secure=SECURE_COOKIE, samesite=COOKIE_SAMESITE, path='/')
    d = load()
    audit(d, 'auth.owner_login', {'username': x.username})
    save(d)
    return r


@app.post('/api/auth/logout')
def logout(request: Request):
    for name in (COOKIE, CUSTOMER_COOKIE):
        token = request.cookies.get(name)
        if token:
            revoke_token(token)
    r = JSONResponse({'ok': True})
    r.delete_cookie(COOKIE, path='/')
    r.delete_cookie(CUSTOMER_COOKIE, path='/')
    r.delete_cookie(CHAT_COOKIE, path='/')
    return r


@app.get('/api/auth/me')
def me(request: Request):
    o = verify(request.cookies.get(COOKIE, ''), 'owner')
    c = verify(request.cookies.get(CUSTOMER_COOKIE, ''), 'customer')
    if not o and not c:
        return {'authenticated': False, 'role': None, 'username': None, 'customer': None}
    if o:
        return {'authenticated': True, 'role': 'owner', 'username': o.get('u'), 'customer': None}
    d = load()
    cust = next((x for x in d['customers'] if x['id'] == c.get('u')), None) if c else None
    if not cust:
        return {'authenticated': False, 'role': None, 'username': None, 'customer': None}
    return {'authenticated': True, 'role': 'customer', 'username': None, 'customer': {k: v for k, v in cust.items() if k != 'password_hash'}}


def _send_email(to_email: str, subject: str, body: str):
    if not SMTP_HOST or not SMTP_FROM:
        raise RuntimeError('SMTP email service is not configured')
    msg = EmailMessage(); msg['From']=SMTP_FROM; msg['To']=to_email; msg['Subject']=subject
    msg['List-Unsubscribe'] = '<mailto:' + SMTP_FROM + '?subject=unsubscribe>'
    msg.set_content(body)
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.ehlo()
            if SMTP_USER: smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)
        return
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.ehlo()
        if SMTP_PORT in {25, 587}:
            smtp.starttls(); smtp.ehlo()
        if SMTP_USER: smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)


def _send_email_safe(to_email, subject, body):
    try: _send_email(to_email, subject, body)
    except Exception: _LOG.exception('Email delivery failed')

def _new_email_token():
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()

def _email_token_matches(raw, stored_hash, expires_at):
    if not raw or not stored_hash or not expires_at:
        return False
    try:
        if datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc):
            return False
    except Exception:
        return False
    return hmac.compare_digest(hashlib.sha256(raw.encode()).hexdigest(), stored_hash)


def validate_password_strength(password: str):
    if len(password) < 10:
        raise HTTPException(400, 'Password must be at least 10 characters long')
    if not re.search(r'[A-Z]', password):
        raise HTTPException(400, 'Password must contain at least one uppercase letter')
    if not re.search(r'\d', password):
        raise HTTPException(400, 'Password must contain at least one number')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=]', password):
        raise HTTPException(400, 'Password must contain at least one special character')


_PASSWORD_FAILS = {}
_PASSWORD_FAILS_LOCK = threading.Lock()
_RESET_RATE = {}
_RESET_RATE_LOCK = threading.Lock()

def _client_ip(request: Request):
    client_ip = request.client.host if request.client else 'unknown'
    trusted = {x.strip() for x in os.getenv('TRUSTED_PROXY_IPS','').split(',') if x.strip()}
    forwarded = request.headers.get('x-forwarded-for','').strip()
    if client_ip in trusted and forwarded:
        return forwarded.split(',')[0].strip() or client_ip
    return client_ip

def _login_key(email, request):
    return f"{email.strip().lower()}:{_client_ip(request)}"

def _check_login_lock(key):
    now_ts = time.time()
    with _PASSWORD_FAILS_LOCK:
        item = _PASSWORD_FAILS.get(key)
        if item and item.get('locked_until', 0) > now_ts:
            return True
        if item and item.get('locked_until', 0) <= now_ts:
            _PASSWORD_FAILS.pop(key, None)
        return False

def _record_login_failure(key):
    now_ts = time.time()
    with _PASSWORD_FAILS_LOCK:
        item = _PASSWORD_FAILS.setdefault(key, {'fails': 0, 'locked_until': 0})
        item['fails'] += 1
        if item['fails'] >= 5:
            item['locked_until'] = now_ts + 900
            item['fails'] = 0

def _clear_login_failures(key):
    with _PASSWORD_FAILS_LOCK:
        _PASSWORD_FAILS.pop(key, None)


@app.post('/api/customer/signup')
def customer_signup(x: CustomerSignup, request: Request, background_tasks: BackgroundTasks):
    validate_password_strength(x.password)
    d = load()
    if any(c.get('email', '').lower() == x.email.lower() and not c.get('deleted_at') for c in d['customers']):
        raise HTTPException(409, 'An account with this email already exists')
    verify_raw, verify_hash = _new_email_token()
    c = {
        'id': uid('c_'), 'name': x.name, 'email': x.email, 'phone': x.phone,
        'password_hash': hash_password(x.password), 'saved': [], 'created_at': now(),
        'updated_at': now(), 'session_version': 1, 'email_verified': False,
        'email_verification_token_hash': verify_hash,
        'email_verification_expires_at': (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
    }
    if REQUIRE_EMAIL_VERIFICATION:
        if not SMTP_HOST or not SMTP_FROM:
            raise HTTPException(503, 'Email verification is enabled but email service is not configured')
    else:
        c['email_verified'] = True
        c.pop('email_verification_token_hash', None)
        c.pop('email_verification_expires_at', None)
    d['customers'].insert(0, c)
    audit(d, 'customer.signup', {'id': c['id']})
    save(d)
    if REQUIRE_EMAIL_VERIFICATION:
        body = 'Use this one-time email verification token in the verification form:\n\n' + verify_raw + '\n\nThis token expires in 24 hours. It is intentionally not placed in a URL.'
        background_tasks.add_task(_send_email_safe, c['email'], 'Verify your EstateAI account', body)
    public = {k: v for k, v in c.items() if 'token' not in k and 'password_hash' not in k}
    r = JSONResponse({'ok': True, 'customer': public, 'email_verification_required': REQUIRE_EMAIL_VERIFICATION})
    if c.get('email_verified'):
        r.set_cookie(CUSTOMER_COOKIE, make_token(c['id'], 'customer', SESSION_DAYS, c.get('session_version', 1)), max_age=SESSION_DAYS * 86400, httponly=True, secure=SECURE_COOKIE, samesite=COOKIE_SAMESITE, path='/')
    return r


@app.get('/api/customer/verify-email')
def verify_email(token: str):
    if not token or len(token) > 200:
        raise HTTPException(400, 'Invalid verification token')
    d = load()
    c = next((z for z in d['customers'] if _email_token_matches(token, z.get('email_verification_token_hash', ''), z.get('email_verification_expires_at', ''))), None)
    if not c:
        raise HTTPException(400, 'Invalid or expired verification token')
    c['email_verified'] = True
    c.pop('email_verification_token_hash', None)
    c.pop('email_verification_expires_at', None)
    c['updated_at'] = now()
    audit(d, 'customer.email_verified', {'id': c['id']})
    save(d)
    return {'ok': True, 'message': 'Email verified successfully. You can now log in.'}


@app.post('/api/customer/login')
def customer_login(x: CustomerLogin, request: Request):
    key = 'customer:' + _login_key(x.email, request)
    if _check_login_lock(key):
        raise HTTPException(423, 'Account temporarily locked. Try again in 15 minutes.')
    d = load()
    c = next((z for z in d['customers'] if z.get('email', '').lower() == x.email.strip().lower()), None)
    if not c or not verify_password(c.get('password_hash', ''), x.password):
        _record_login_failure(key)
        raise HTTPException(401, 'Invalid customer login')
    _clear_login_failures(key)
    if not c.get('email_verified', True):
        raise HTTPException(403, 'Please verify your email before logging in')
    if re.fullmatch(r'[0-9a-f]{64}', c.get('password_hash', '') or ''):
        c['password_hash'] = hash_password(x.password)
        save(d)
    r = JSONResponse({'ok': True, 'customer': {k: v for k, v in c.items() if k != 'password_hash'}})
    r.set_cookie(CUSTOMER_COOKIE, make_token(c['id'], 'customer', SESSION_DAYS, c.get('session_version', 1)), max_age=SESSION_DAYS * 86400, httponly=True, secure=SECURE_COOKIE, samesite=COOKIE_SAMESITE, path='/')
    return r


@app.get('/api/customer/me')
def customer_me(c=Depends(customer)):
    d = load()
    x = next((z for z in d['customers'] if z['id'] == c['u']), None)
    if not x:
        raise HTTPException(404, 'Customer not found')
    return {k: v for k, v in x.items() if k != 'password_hash'}


@app.put('/api/customer/me')
def customer_update(x: CustomerProfile, c=Depends(customer)):
    d = load()
    z = next((q for q in d['customers'] if q['id'] == c['u']), None)
    if not z:
        raise HTTPException(404, 'Customer not found')
    new_email = x.email.strip().lower()
    if new_email and any(q['id'] != z['id'] and q.get('email', '').lower() == new_email for q in d['customers']):
        raise HTTPException(409, 'An account with this email already exists')
    if x.phone and not valid_phone(x.phone):
        raise HTTPException(400, 'Invalid phone number')
    xdata = x.model_dump()
    xdata['email'] = new_email
    xdata['phone'] = normalize_phone(x.phone) if x.phone else ''
    z.update(xdata)
    z['updated_at'] = now()
    audit(d, 'customer.profile_updated', {'id': z['id']})
    save(d)
    return {k: v for k, v in z.items() if k != 'password_hash'}


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=10, max_length=128)


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        v = v.strip().lower()
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', v):
            raise ValueError('Invalid email address')
        return v


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=10, max_length=128)


@app.post('/api/customer/password-change')
def customer_password_change(x: PasswordChange, request: Request, c=Depends(customer)):
    validate_password_strength(x.new_password)
    d = load()
    z = next((q for q in d['customers'] if q.get('id') == c['u'] and not q.get('deleted_at')), None)
    if not z or not verify_password(z.get('password_hash', ''), x.current_password):
        raise HTTPException(401, 'Current password is incorrect')
    z['password_hash'] = hash_password(x.new_password)
    z['session_version'] = int(z.get('session_version', 1) or 1) + 1
    z['updated_at'] = now()
    audit(d, 'customer.password_changed', {'id': z['id']})
    save(d)
    revoke_token(request.cookies.get(CUSTOMER_COOKIE, ''))
    r = JSONResponse({'ok': True, 'message': 'Password changed. Please log in again.'})
    r.delete_cookie(CUSTOMER_COOKIE, path='/')
    return r


@app.post('/api/customer/password-reset/request')
def password_reset_request(x: PasswordResetRequest, background_tasks: BackgroundTasks):
    email=x.email.strip().lower(); now_ts=time.time()
    with _RESET_RATE_LOCK:
        recent=[t for t in _RESET_RATE.get(email,[]) if now_ts-t<3600]
        if len(recent)>=3:
            return {'ok':True,'message':'If an account exists for that email, reset instructions have been sent.'}
        recent.append(now_ts); _RESET_RATE[email]=recent
        if len(_RESET_RATE)>10000:
            for k in list(_RESET_RATE)[:5000]:
                if not _RESET_RATE[k] or now_ts-_RESET_RATE[k][-1]>3600: _RESET_RATE.pop(k,None)
    d=load(); c=next((z for z in d['customers'] if z.get('email','').lower()==email and not z.get('deleted_at')),None)
    if c and SMTP_HOST and SMTP_FROM:
        raw,token_hash=_new_email_token(); c['password_reset_token_hash']=token_hash
        c['password_reset_expires_at']=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(); c['updated_at']=now(); save(d)
        body='Use this one-time password reset token in the password reset form:\n\n'+raw+'\n\nThis token expires in 1 hour. It is intentionally not placed in a URL.'
        background_tasks.add_task(_send_email_safe,c['email'],'Reset your EstateAI password',body)
    return {'ok':True,'message':'If an account exists for that email, reset instructions have been sent.'}


@app.post('/api/customer/password-reset/confirm')
def password_reset_confirm(x: PasswordResetConfirm):
    validate_password_strength(x.new_password)
    d = load()
    c = next((z for z in d['customers'] if _email_token_matches(x.token, z.get('password_reset_token_hash', ''), z.get('password_reset_expires_at', ''))), None)
    if not c:
        raise HTTPException(400, 'Invalid or expired reset token')
    c['password_hash'] = hash_password(x.new_password)
    c['session_version'] = int(c.get('session_version', 1) or 1) + 1
    c.pop('password_reset_token_hash', None)
    c.pop('password_reset_expires_at', None)
    c['updated_at'] = now()
    audit(d, 'customer.password_reset', {'id': c['id']})
    save(d)
    return {'ok': True}


@app.delete('/api/customer/delete')
def customer_delete(request: Request, c=Depends(customer)):
    d = load()
    z = next((q for q in d['customers'] if q.get('id') == c['u'] and not q.get('deleted_at')), None)
    if not z:
        raise HTTPException(404, 'Customer not found')
    z['deleted_at'] = now()
    z['updated_at'] = now()
    z['email'] = 'deleted+' + z['id'] + '@invalid.local'
    z['name'] = 'Deleted customer'
    z['phone'] = ''
    z['saved'] = []
    z.pop('password_hash', None)
    for collection in ('leads', 'visits', 'messages'):
        for item in d[collection]:
            if item.get('customer_id') == c['u']:
                item['customer_id'] = ''
                item['updated_at'] = now()
    audit(d, 'customer.account_deleted', {'id': c['u']})
    save(d)
    revoke_token(request.cookies.get(CUSTOMER_COOKIE, ''))
    r = JSONResponse({'ok': True})
    r.delete_cookie(CUSTOMER_COOKIE, path='/')
    r.delete_cookie(CHAT_COOKIE, path='/')
    return r


@app.get('/api/customer/export')
def customer_export(c=Depends(customer)):
    d = load()
    z = next((q for q in d['customers'] if q.get('id') == c['u'] and not q.get('deleted_at')), None)
    if not z:
        raise HTTPException(404, 'Customer not found')
    safe_customer = {k: v for k, v in z.items() if not k.endswith('_hash') and 'token' not in k and k != 'password_hash'}
    return {
        'customer': safe_customer,
        'leads': [x for x in d['leads'] if x.get('customer_id') == c['u']],
        'visits': [x for x in d['visits'] if x.get('customer_id') == c['u']],
        'messages': [x for x in d['messages'] if x.get('customer_id') == c['u']],
    }


# ---------- Public data ----------
@app.get('/api/settings')
def settings():
    s = load()['settings']
    return {k: v for k, v in s.items() if k not in ['ai_business_context']}


@app.get('/api/properties')
def properties(
    q: str = '',
    location: str = '',
    ptype: str = '',
    purpose: str = '',
    bhk: str = '',
    min_price: float = 0,
    max_price: float = 0,
    offset: int = 0,
    limit: int = 50,
):
    if len(q) > MAX_QUERY_LENGTH or len(location) > 200:
        raise HTTPException(400, 'Search query is too long')
    if min_price < 0 or max_price < 0:
        raise HTTPException(400, 'Price cannot be negative')
    if max_price and min_price and max_price < min_price:
        raise HTTPException(400, 'max_price cannot be lower than min_price')
    offset = max(0, min(offset, 10000))
    limit = max(1, min(limit, 100))
    d = load()
    arr = public_props(d)
    q = q.lower().strip()
    location = location.lower().strip()
    ptype = ptype.lower().strip()
    bhk = bhk.lower().strip()
    purpose = purpose.lower().strip()
    if q:
        arr = [p for p in arr if q in json.dumps(p, ensure_ascii=False).lower()]
    if location:
        arr = [p for p in arr if location in str(p.get('location', '')).lower() or location in str(p.get('city', '')).lower() or location in str(p.get('locality', '')).lower()]
    if ptype:
        arr = [p for p in arr if ptype in str(p.get('type', '')).lower()]
    if purpose:
        arr = [p for p in arr if purpose in str(p.get('purpose', '')).lower()]
    if bhk:
        arr = [p for p in arr if bhk in str(p.get('bhk', '')).lower()]
    if min_price:
        arr = [p for p in arr if float(p.get('price', 0) or 0) >= min_price]
    if max_price:
        arr = [p for p in arr if float(p.get('price', 0) or 0) <= max_price]
    arr.sort(key=lambda p: (not bool(p.get('featured', False)), -float(p.get('price', 0) or 0), str(p.get('title', '')).lower()))
    return arr[offset:offset + limit]


def _increment_property_view(pid):
    if DATABASE_URL:
        conn = _pg_request_conn()
        if conn is not None:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(73421902)")
            d = _load_pg(conn)
            original = next((x for x in d['properties'] if x.get('id') == pid), None)
            if original is None or not original.get('published') or original.get('status') in {'Draft', 'Archived'}:
                return None
            original['views'] = int(original.get('views', 0) or 0) + 1
            d['metrics']['property_views'] = int(d['metrics'].get('property_views', 0) or 0) + 1
            audit(d, 'property.viewed', {'id': pid})
            _save_pg(conn, d)
            return copy.deepcopy(original)
        pool = _pg_pool()
        with pool.connection() as local_conn:
            with local_conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(73421902)")
            d = _load_pg(local_conn)
            original = next((x for x in d['properties'] if x.get('id') == pid), None)
            if original is None or not original.get('published') or original.get('status') in {'Draft', 'Archived'}:
                return None
            original['views'] = int(original.get('views', 0) or 0) + 1
            d['metrics']['property_views'] = int(d['metrics'].get('property_views', 0) or 0) + 1
            audit(d, 'property.viewed', {'id': pid})
            _save_pg(local_conn, d)
            local_conn.commit()
            return copy.deepcopy(original)
    with _DB_FILE_LOCK:
        d = load()
        original = next((x for x in d['properties'] if x.get('id') == pid), None)
        if original is None or not original.get('published') or original.get('status') in {'Draft', 'Archived'}:
            return None
        original['views'] = int(original.get('views', 0) or 0) + 1
        d['metrics']['property_views'] = int(d['metrics'].get('property_views', 0) or 0) + 1
        audit(d, 'property.viewed', {'id': pid})
        save(d)
        return copy.deepcopy(original)

@app.get('/api/properties/{pid}')
def property_detail(pid: str):
    p = _increment_property_view(pid)
    if not p:
        raise HTTPException(404, 'Property not found')
    p.pop('is_demo', None)
    return p


@app.post('/api/properties/{pid}/view')
def increment_view(pid: str):
    p = _increment_property_view(pid)
    if not p:
        raise HTTPException(404, 'Property not found')
    return {'ok': True, 'views': int(p.get('views', 0) or 0)}


@app.post('/api/events/{kind}')
def event(kind: str):
    allowed = {'call': 'calls', 'whatsapp': 'whatsapp', 'search': 'searches'}
    key = allowed.get(kind)
    if not key:
        raise HTTPException(400, 'Unknown event type')
    d = load()
    d['metrics'][key] = int(d['metrics'].get(key, 0) or 0) + 1
    audit(d, 'public.' + kind)
    save(d)
    return {'ok': True}


# ---------- Saved properties ----------
@app.post('/api/customer/saved/{pid}')
def save_property(pid: str, c=Depends(customer)):
    d = load()
    p = next((x for x in public_props(d) if x['id'] == pid), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    z = next(x for x in d['customers'] if x['id'] == c['u'])
    z.setdefault('saved', [])
    if pid not in z['saved']:
        z['saved'].append(pid)
    save(d)
    return z['saved']


@app.delete('/api/customer/saved/{pid}')
def unsave_property(pid: str, c=Depends(customer)):
    d = load()
    z = next(x for x in d['customers'] if x['id'] == c['u'])
    z['saved'] = [x for x in z.get('saved', []) if x != pid]
    save(d)
    return z['saved']


@app.get('/api/customer/activity')
def customer_activity(c=Depends(customer)):
    d = load()
    cid = c['u']
    return {
        'saved': next((x.get('saved', []) for x in d['customers'] if x['id'] == cid), []),
        'leads': [x for x in d['leads'] if x.get('customer_id') == cid],
        'visits': [x for x in d['visits'] if x.get('customer_id') == cid],
        'messages': [x for x in d['messages'] if x.get('customer_id') == cid]
    }


# ---------- Leads / visits ----------
@app.post('/api/leads')
def create_lead(l: Lead, request: Request):
    if not l.consent:
        raise HTTPException(400, 'Consent is required')
    d = load()
    c = optional_customer(request)
    cid = c['u'] if c else ''
    prop = next((p for p in public_props(d) if p.get('id') == l.property_id), None) if l.property_id else None
    if l.property_id and not prop:
        raise HTTPException(404, 'Property not found')
    # Basic duplicate suppression for repeated submissions from the same contact/property.
    email = l.email.strip().lower()
    phone = normalize_phone(l.phone)
    recent_cutoff = datetime.now(timezone.utc).timestamp() - 300
    for old in d['leads'][:500]:
        try:
            old_ts = datetime.fromisoformat(old.get('created_at', '').replace('Z', '+00:00')).timestamp()
        except Exception:
            old_ts = 0
        if old_ts >= recent_cutoff and (email and old.get('email', '').lower() == email or phone and normalize_phone(old.get('phone', '')) == phone) and old.get('property_id', '') == l.property_id:
            return old
    item = {'id': uid('lead_'), **l.model_dump(exclude={'customer_id'}), 'customer_id': cid, 'status': 'New', 'score': 'Warm', 'created_at': now()}
    d['leads'].insert(0, item)
    d['notifications'].insert(0, {'id': uid('n_'), 'type': 'lead', 'title': 'New customer lead', 'text': l.name + ' submitted an enquiry', 'at': now(), 'read': False})
    d['metrics']['enquiries'] = int(d['metrics'].get('enquiries', 0) or 0) + 1
    audit(d, 'lead.created', {'lead_id': item['id'], 'property_id': l.property_id})
    save(d)
    return item


@app.post('/api/visits')
def create_visit(v: Visit, request: Request):
    if not v.consent:
        raise HTTPException(400, 'Consent is required')
    d = load()
    c = optional_customer(request)
    cid = c['u'] if c else ''
    prop = next((p for p in public_props(d) if p.get('id') == v.property_id), None) if v.property_id else None
    if v.property_id and not prop:
        raise HTTPException(404, 'Property not found')
    if not valid_phone(v.phone):
        raise HTTPException(400, 'Invalid phone number')
    try:
        visit_dt = datetime.strptime(f'{v.date} {v.time}', '%Y-%m-%d %H:%M')
        if visit_dt < datetime.now().replace(tzinfo=None):
            raise HTTPException(400, 'Visit time cannot be in the past')
    except ValueError:
        raise HTTPException(400, 'Invalid visit date or time')
    # Avoid duplicate booking requests for the same property/time/contact.
    phone = normalize_phone(v.phone)
    for old in d['visits'][:500]:
        if old.get('date') == v.date and old.get('time') == v.time and old.get('property_id') == v.property_id and normalize_phone(old.get('phone', '')) == phone and old.get('status') not in {'Cancelled'}:
            return {'ok': True, 'visit': old, 'message': 'This visit request already exists.'}
    item = {'id': uid('visit_'), **v.model_dump(exclude={'customer_id'}), 'customer_id': cid, 'status': 'Pending', 'created_at': now(), 'updated_at': now()}
    d['visits'].insert(0, item)
    d['notifications'].insert(0, {'id': uid('n_'), 'type': 'visit', 'title': 'New site-visit request', 'text': v.name + ' requested a visit', 'at': now(), 'read': False})
    d['metrics']['bookings'] = int(d['metrics'].get('bookings', 0) or 0) + 1
    audit(d, 'visit.created', {'visit_id': item['id'], 'property_id': v.property_id})
    save(d)
    return {'ok': True, 'visit': item, 'message': 'Request submitted. The property team will confirm the visit.'}


# ---------- AI ----------
@app.post('/api/chat')
def chat(c: Chat, request: Request):
    d = load()
    cust = optional_customer(request)
    published = public_props(d)
    sid, created_chat_cookie = chat_session(request, c.session_id, cust['u'] if cust else '', d)
    msg = c.message.strip()
    if not msg and not c.image_data:
        raise HTTPException(400, 'Message or image is required')
    low = msg.lower()

    if c.property_id and not any(p.get('id') == c.property_id for p in published):
        raise HTTPException(404, 'Property not found')

    candidates = []
    terms = [t for t in re.findall(r'\w+', low, flags=re.UNICODE) if len(t) > 2]
    for p in published:
        searchable = ' '.join([
            str(p.get('title', '')),
            str(p.get('purpose', '')),
            str(p.get('type', '')),
            str(p.get('bhk', '')),
            str(p.get('price', '')),
            str(p.get('location', '')),
            str(p.get('locality', '')),
            str(p.get('city', '')),
            str(p.get('state', '')),
            str(p.get('area', '')),
            str(p.get('status', '')),
            ' '.join(map(str, p.get('amenities', []) or [])),
        ]).lower()
        score = sum(1 for term in terms if term in searchable)
        if score:
            candidates.append((score, p))
    candidates = [p for _, p in sorted(candidates, key=lambda x: (-x[0], str(x[1].get('title', ''))))[:8]]

    context_rows = []
    for p in (candidates or published[:12]):
        context_rows.append(
            'ID:' + str(p.get('id', '')) + ' | ' + str(p.get('title', '')) +
            ' | ' + str(p.get('purpose', '')) + ' | ' + str(p.get('type', '')) +
            ' | ' + str(p.get('bhk', '')) + ' | Rs ' + str(p.get('price', '')) +
            ' | ' + str(p.get('location', '')) + ' | ' + str(p.get('area', '')) +
            ' | ' + str(p.get('status', '')) + ' | Amenities: ' +
            ', '.join(map(str, p.get('amenities', []) or []))
        )
    context = '\n'.join(context_rows)[:12000]

    s = d['settings']
    business_info = (
        '\n\nBusiness: ' + str(s.get('brand', '')) + '.'
        + ' Owner/contact: ' + str(s.get('owner_name', ''))
        + ', phone ' + str(s.get('phone', ''))
        + ', WhatsApp ' + str(s.get('whatsapp', ''))
        + '. Hours: ' + str(s.get('business_hours', ''))
        + '. About: ' + str(s.get('about', '')) + '.'
    )
    rules = (
        '\n\nCURRENT PUBLISHED PROPERTY DATA:\n' + context + '\n\n'
        'Rules:\n'
        '1. Reply in the SAME language the customer uses (English, Hindi, Hinglish, Marathi, Tamil, Bengali, Telugu, Kannada, Gujarati, Punjabi, Malayalam, Urdu, or any other language).\n'
        '2. Use ONLY the published property data above. Never invent price, availability, location, legal facts or owner data.\n'
        '3. If a fact is not in this data or settings, say you do not have confirmed information.\n'
        '4. Never reveal unpublished properties or private owner dashboard data.\n'
        '5. Guide customers to Call / WhatsApp / Site Visit when relevant.\n'
        '6. Keep answers natural, professional, sales-assistant-like - not robotic.\n'
        '7. For general real estate advice (loans, registration, vastu, locality), you may answer helpfully but always clarify it is not legal or professional consultation.'
    )
    system = (s.get('ai_business_context') or DEFAULT['settings']['ai_business_context']) + business_info + rules

    history = get_session_history(d, sid, limit=MAX_MESSAGE_HISTORY)
    messages = [{'role': 'system', 'content': system}]
    for h in history:
        messages += [{'role': 'user', 'content': h['user']}, {'role': 'assistant', 'content': h['assistant']}]
    messages.append({'role': 'user', 'content': msg})

    answer = groq(messages, model=(os.getenv('GROQ_VISION_MODEL', 'qwen/qwen3.8-27b') if c.image_data else os.getenv('GROQ_TEXT_MODEL', 'openai/gpt-oss-120b')), image_data=(c.image_data or None))
    if not answer:
        if any(x in low for x in ['number', 'phone', 'contact', 'call', 'whatsapp', 'नंबर', 'फोन', 'व्हाट्सएप']):
            owner_name = s.get('owner_name') or s.get('brand') or 'the property team'
            phone = s.get('phone') or ''
            wa = normalize_phone(s.get('whatsapp') or '')
            contact_bits = []
            if phone: contact_bits.append('Call: ' + phone)
            if wa: contact_bits.append('WhatsApp: +' + wa)
            answer = owner_name + ' contact details: ' + (' · '.join(contact_bits) if contact_bits else 'the contact number is not configured yet. Please use the contact buttons shown on the website.')
        elif candidates:
            answer = 'I found ' + str(len(candidates)) + ' published property option(s) that may match. Open the property cards below to compare. Tell me your budget, location and BHK to narrow it down.'
        else:
            answer = s.get('ai_greeting') or 'Tell me your preferred location, budget, BHK or property type and I will help you find matching published properties.'

    item = {'id': uid('msg_'), 'session_id': sid, 'customer_id': cust['u'] if cust else '', 'user': msg, 'assistant': answer, 'property_id': c.property_id, 'image_attached': bool(c.image_data), 'at': now()}
    d['messages'].append(item)
    append_session_message(sid, item)
    d['metrics']['chat_sessions'] = len(set(x.get('session_id') for x in d['messages']))
    audit(d, 'ai.chat', {'message_id': item['id'], 'customer_id': item['customer_id']})
    save(d)

    resp = JSONResponse({'answer': answer, 'matches': candidates[:6], 'session_id': sid, 'contact': {'phone': s.get('phone', ''), 'whatsapp': whatsapp_url(s.get('whatsapp', ''))}})
    if created_chat_cookie:
        resp.set_cookie(CHAT_COOKIE, sid, max_age=SESSION_DAYS * 86400, httponly=True, secure=SECURE_COOKIE, samesite=COOKIE_SAMESITE, path='/')
    return resp


# ---------- Owner ----------
@app.get('/api/owner/data')
def owner_data(limit: int | None = None, offset: int = 0, _: dict = Depends(owner)):
    d=load(); customers=[{k:v for k,v in c.items() if k!='password_hash'} for c in d['customers']]
    collections={'properties':[p for p in d['properties'] if not p.get('deleted_at')],'customers':customers,'leads':d['leads'],'visits':d['visits'],'messages':d['messages'],'notifications':d['notifications'],'audit':d['audit']}
    if limit is not None:
        limit=max(1,min(int(limit),500)); offset=max(0,int(offset))
        for k,v in list(collections.items()): collections[k]=v[offset:offset+limit]
        collections['pagination']={'limit':limit,'offset':offset}
    return {'settings':d['settings'],**collections,'metrics':d['metrics']}


@app.post('/api/settings')
def update_settings(s: Settings, _: dict = Depends(owner)):
    d = load()
    incoming = s.model_dump(exclude_unset=True)
    merged = {**d.get('settings', {}), **incoming}
    d['settings'] = Settings(**merged).model_dump()
    audit(d, 'settings.updated')
    save(d)
    return d['settings']


PROPERTY_FIELDS = {
    'title': (str, 200), 'purpose': (str, 30), 'type': (str, 50), 'price': (int, 0),
    'bhk': (str, 30), 'bathrooms': (str, 20), 'area': (str, 60), 'built_up_area': (str, 60),
    'plot_area': (str, 60), 'floor': (str, 30), 'total_floors': (str, 30),
    'location': (str, 300), 'locality': (str, 120), 'city': (str, 120), 'state': (str, 120),
    'pincode': (str, 20), 'map_url': (str, 1000), 'status': (str, 60), 'facing': (str, 40),
    'furnishing': (str, 60), 'parking': (str, 60), 'construction_year': (str, 10),
    'rera': (str, 100), 'description': (str, 5000), 'amenities': (list, 30),
    'featured': (bool, None), 'published': (bool, None), 'is_demo': (bool, None),
}


def normalize_property(data, existing=None):
    if not isinstance(data, dict):
        raise HTTPException(422, 'Property must be an object')
    out = dict(existing or {})
    for key, value in data.items():
        if key in {'id', 'views', 'created_at', 'updated_at'}:
            continue
        if key not in PROPERTY_FIELDS:
            continue
        typ, limit = PROPERTY_FIELDS[key]
        if typ is bool:
            if not isinstance(value, bool):
                raise HTTPException(422, f'{key} must be boolean')
            out[key] = value
        elif typ is int:
            try:
                num = int(value)
            except (TypeError, ValueError):
                raise HTTPException(422, f'{key} must be a number')
            if num < 0:
                raise HTTPException(422, f'{key} cannot be negative')
            out[key] = num
        elif typ is list:
            if not isinstance(value, list) or len(value) > limit:
                raise HTTPException(422, f'{key} is invalid')
            out[key] = [str(x)[:100] for x in value[:limit]]
        else:
            text = str(value or '').strip()
            if len(text) > limit:
                raise HTTPException(422, f'{key} is too long')
            out[key] = text
    if out.get('map_url') and not valid_http_url(out['map_url']):
        raise HTTPException(422, 'map_url must be a valid http(s) URL')
    out.setdefault('title', 'Untitled property')
    out.setdefault('purpose', 'Buy')
    out.setdefault('type', 'Property')
    out.setdefault('price', 0)
    out.setdefault('description', '')
    out.setdefault('amenities', [])
    out.setdefault('published', False)
    out.setdefault('featured', False)
    out.setdefault('is_demo', False)
    return out


@app.post('/api/properties')
def add_property(p: dict, _: dict = Depends(owner)):
    d = load()
    p = normalize_property(p)
    p['id'] = uid('p_')
    p['views'] = 0
    p['images'] = []
    p['created_at'] = now()
    p['updated_at'] = now()
    d['properties'].insert(0, p)
    audit(d, 'property.created', {'id': p['id']})
    save(d)
    return p


@app.put('/api/properties/{pid}')
def edit_property(pid: str, p: dict, _: dict = Depends(owner)):
    d = load()
    old = next((x for x in d['properties'] if x.get('id') == pid), None)
    if not old:
        raise HTTPException(404, 'Property not found')
    merged = dict(old)
    merged.update({k: v for k, v in p.items() if k not in {'id', 'views', 'created_at', 'updated_at'}})
    normalized = normalize_property(merged, existing=old)
    normalized['id'] = pid
    normalized['views'] = old.get('views', 0)
    normalized['images'] = merged.get('images', old.get('images', []))
    normalized['is_demo'] = bool(merged.get('is_demo', old.get('is_demo', False)))
    normalized['featured'] = bool(merged.get('featured', old.get('featured', False)))
    normalized['published'] = bool(merged.get('published', old.get('published', False)))
    normalized['created_at'] = old.get('created_at', now())
    normalized['updated_at'] = now()
    d['properties'][d['properties'].index(old)] = normalized
    audit(d, 'property.updated', {'id': pid})
    save(d)
    return normalized


@app.delete('/api/properties/{pid}')
def delete_property(pid: str, _: dict = Depends(owner)):
    d = load()
    p = next((x for x in d['properties'] if x.get('id') == pid and not x.get('deleted_at')), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    p['deleted_at'] = now(); p['published'] = False; p['updated_at'] = now()
    for c in d['customers']:
        c['saved'] = [x for x in c.get('saved', []) if x != pid]
    audit(d, 'property.deleted', {'id': pid})
    save(d)
    return {'ok': True}


@app.post('/api/properties/{pid}/publish')
def publish(pid: str, published: bool = True, _: dict = Depends(owner)):
    d = load()
    p = next((x for x in d['properties'] if x['id'] == pid), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    p['published'] = published
    p['status'] = 'Published' if published and p.get('status') == 'Draft' else p.get('status', 'Ready to Move')
    p['updated_at'] = now()
    audit(d, 'property.published' if published else 'property.unpublished', {'id': pid})
    save(d)
    return p


@app.get('/api/properties/{pid}/similar')
def similar_properties(pid: str, limit: int = 6):
    d = load()
    p = next((x for x in public_props(d) if x.get('id') == pid), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    limit = max(1, min(limit, 20))
    pool = [x for x in public_props(d) if x.get('id') != pid]
    scored = []
    for x in pool:
        score = 0
        if x.get('city') and str(x.get('city', '')).lower() == str(p.get('city', '')).lower(): score += 4
        if x.get('locality') and x.get('locality') == p.get('locality'): score += 3
        if x.get('type') == p.get('type'): score += 2
        if x.get('purpose') == p.get('purpose'): score += 2
        if x.get('bhk') == p.get('bhk'): score += 1
        try:
            if p.get('price') and x.get('price'):
                ratio = abs(float(x['price']) - float(p['price'])) / max(float(p['price']), 1)
                if ratio <= 0.2: score += 2
        except Exception: pass
        scored.append((score, x))
    return [x for _, x in sorted(scored, key=lambda z: (-z[0], str(z[1].get('title','')).lower()))[:limit]]


@app.get('/api/properties/{pid}/share')
def share_property(pid: str, request: Request):
    p = next((x for x in public_props(load()) if x.get('id') == pid), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    base = PUBLIC_BASE_URL or str(request.base_url).rstrip('/')
    return {'url': base + '/#property=' + pid, 'title': p.get('title', 'Property'), 'text': str(p.get('title', 'Property')) + ' - ' + str(p.get('location', ''))}


class BulkPropertyAction(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=200)
    action: str = Field(min_length=1, max_length=30)


@app.post('/api/owner/properties/bulk')
def bulk_properties(x: BulkPropertyAction, _: dict = Depends(owner)):
    allowed = {'publish', 'unpublish', 'archive', 'delete'}
    if x.action not in allowed:
        raise HTTPException(400, 'Invalid bulk action')
    d = load()
    ids = set(x.ids)
    changed = 0
    for p in d['properties']:
        if p.get('id') not in ids: continue
        if x.action == 'delete':
            p['deleted_at'] = now(); p['published'] = False
        elif x.action == 'publish': p['published'] = True; p['status'] = 'Published' if p.get('status') == 'Draft' else p.get('status','Ready to Move')
        elif x.action == 'unpublish': p['published'] = False
        elif x.action == 'archive': p['published'] = False; p['status'] = 'Archived'
        p['updated_at'] = now(); changed += 1
    audit(d, 'properties.bulk_updated', {'action': x.action, 'count': changed})
    save(d)
    return {'ok': True, 'changed': changed}


def _csv_safe(value):
    text=str(value if value is not None else '')
    return "'"+text if text.startswith(('=','+','-','@')) else text


@app.get('/api/owner/properties/export.csv')
def export_properties_csv(_: dict = Depends(owner)):
    d = load(); out = io.StringIO(); fields = ['id','title','purpose','type','price','bhk','area','location','city','state','status','published','featured','is_demo','views','created_at','updated_at']
    w = csv.DictWriter(out, fieldnames=fields); w.writeheader()
    for p in d['properties']:
        w.writerow({k: _csv_safe(p.get(k, '')) for k in fields})
    return Response(out.getvalue(), media_type='text/csv; charset=utf-8', headers={'Content-Disposition': 'attachment; filename=properties.csv'})


@app.post('/api/owner/properties/import.csv')
def import_properties_csv(payload: dict, _: dict = Depends(owner)):
    raw = str(payload.get('csv', ''))
    if len(raw) > 2_000_000: raise HTTPException(413, 'CSV is too large')
    reader = csv.DictReader(io.StringIO(raw)); d = load(); count = 0
    for row in reader:
        if not row.get('title') and not row.get('location'): continue
        clean_row = dict(row)
        for bool_key in ('published', 'featured', 'is_demo'):
            raw_bool = str(clean_row.get(bool_key, '')).strip().lower()
            clean_row[bool_key] = raw_bool in {'true', '1', 'yes', 'y', 'on'}
        if clean_row.get('price', '') == '':
            clean_row['price'] = 0
        p = normalize_property(clean_row)
        p['id'] = uid('p_'); p['views'] = 0; p['images'] = []; p['created_at'] = now(); p['updated_at'] = now()
        d['properties'].insert(0, p); count += 1
        if count >= 500: break
    audit(d, 'properties.csv_imported', {'count': count}); save(d)
    return {'ok': True, 'imported': count}


def _encode_image(image, content_type, max_dim, quality=82):
    from PIL import Image
    if max(image.size) > max_dim:
        image.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
    out = io.BytesIO()
    if content_type == 'image/jpeg':
        if image.mode not in ('RGB', 'L'):
            bg = Image.new('RGB', image.size, 'white')
            bg.paste(image, mask=image.getchannel('A') if 'A' in image.getbands() else None)
            image = bg
        image.save(out, format='JPEG', quality=quality, optimize=True, progressive=True)
    elif content_type == 'image/webp':
        image.save(out, format='WEBP', quality=quality, method=6)
    else:
        image.save(out, format='PNG', optimize=True)
    return out.getvalue()


def optimize_image_bytes(content_type, raw):
    try:
        from PIL import Image
        image = Image.open(io.BytesIO(raw))
        image.load()
        optimized = _encode_image(image, content_type, 2400, 82)
        return optimized if len(optimized) < len(raw) else raw
    except Exception:
        return raw


def make_thumbnail_data(content_type, raw):
    try:
        from PIL import Image
        image = Image.open(io.BytesIO(raw))
        image.load()
        thumb = _encode_image(image, content_type, 600, 76)
        thumb_type = content_type
        return 'data:' + thumb_type + ';base64,' + base64.b64encode(thumb).decode()
    except Exception:
        return ''


@app.post('/api/properties/{pid}/images')
async def image_upload(pid: str, file: UploadFile = File(...), _: dict = Depends(owner)):
    d = load()
    p = next((x for x in d['properties'] if x.get('id') == pid), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    content_type = (file.content_type or '').lower()
    if content_type not in {'image/jpeg', 'image/png', 'image/webp'}:
        raise HTTPException(400, 'Only JPG, PNG or WebP images are allowed')
    if len(p.get('images', [])) >= MAX_PROPERTY_IMAGES:
        raise HTTPException(400, 'Maximum image limit reached for this property')
    raw = await file.read(MAX_IMAGE_BYTES + 1)
    if len(raw) > MAX_IMAGE_BYTES:
        raise HTTPException(413, 'Max image size is ' + str(MAX_UPLOAD_MB) + ' MB')
    if not validate_image_bytes(content_type, raw):
        raise HTTPException(400, 'Invalid or corrupted image file')
    raw = optimize_image_bytes(content_type, raw)

    original_name = os.path.basename(file.filename or 'image')
    safe_stem = re.sub(r'[^A-Za-z0-9._-]+', '_', Path(original_name).stem)[:80] or 'image'
    image = {'id': uid('img_'), 'name': original_name[:180], 'url': '', 'data': '', 'public_id': '', 'thumb_url': ''}
    if CLOUDINARY_URL:
        try:
            import cloudinary
            import cloudinary.uploader
            cloudinary.config(cloudinary_url=CLOUDINARY_URL)
            result = cloudinary.uploader.upload(
                raw,
                folder='estateai/properties',
                resource_type='image',
                public_id=safe_stem + '_' + uuid.uuid4().hex[:8],
            )
            image['url'] = result.get('secure_url', '')
            image['public_id'] = result.get('public_id', '')
            if image['url']:
                image['thumb_url'] = image['url'].replace('/upload/', '/upload/w_600,h_400,c_fill,q_auto,f_auto/')
            if not image['url']:
                raise RuntimeError('Cloudinary returned no secure URL')
        except ImportError:
            image['data'] = 'data:' + content_type + ';base64,' + base64.b64encode(raw).decode()
        except Exception as exc:
            _LOG.exception('Cloudinary upload failed')
            raise HTTPException(502, 'Image storage upload failed') from exc
    else:
        if os.getenv('ALLOW_LOCAL_IMAGE_FALLBACK', 'true').lower() != 'true':
            raise HTTPException(503, 'Image storage is not configured. Set CLOUDINARY_URL before uploading images.')
        image['data'] = 'data:' + content_type + ';base64,' + base64.b64encode(raw).decode()
    if not image.get('thumb_url'):
        image['thumb_url'] = make_thumbnail_data(content_type, raw) or image.get('url') or image.get('data')

    p.setdefault('images', []).append(image)
    audit(d, 'property.image_uploaded', {'property_id': pid, 'name': original_name})
    save(d)
    return p


@app.delete('/api/properties/{pid}/images/{image_id}')
def image_delete(pid: str, image_id: str, _: dict = Depends(owner)):
    d = load()
    p = next((x for x in d['properties'] if x['id'] == pid), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    target = next((x for x in p.get('images', []) if x.get('id') == image_id), None)
    if not target:
        raise HTTPException(404, 'Image not found')
    if CLOUDINARY_URL and target.get('public_id'):
        try:
            import cloudinary
            import cloudinary.uploader
            cloudinary.config(cloudinary_url=CLOUDINARY_URL)
            cloudinary.uploader.destroy(target['public_id'], resource_type='image')
        except Exception as exc:
            _LOG.warning('Cloudinary image deletion failed for %s: %s', target.get('public_id'), exc)
    p['images'] = [x for x in p.get('images', []) if x.get('id') != image_id]
    audit(d, 'property.image_deleted', {'property_id': pid, 'image_id': image_id})
    save(d)
    return p


@app.post('/api/owner/demo-data/remove')
def remove_demo_data(_: dict = Depends(owner)):
    d = load()
    before = len(d['properties'])
    d['properties'] = [p for p in d['properties'] if not p.get('is_demo')]
    removed = before - len(d['properties'])
    audit(d, 'demo_data.removed', {'count': removed})
    save(d)
    return {'ok': True, 'removed': removed}


@app.post('/api/owner/leads/{lid}/status')
def lead_status(lid: str, x: StatusUpdate, _: dict = Depends(owner)):
    d = load()
    z = next((q for q in d['leads'] if q['id'] == lid), None)
    if not z:
        raise HTTPException(404, 'Lead not found')
    allowed = {'New', 'Contacted', 'Visit Scheduled', 'Negotiation', 'Closed', 'Lost', 'Qualified', 'Won'}
    if x.status not in allowed:
        raise HTTPException(400, 'Invalid lead status')
    z['status'] = x.status
    z['updated_at'] = now()
    audit(d, 'lead.status_updated', {'id': lid, 'status': x.status})
    save(d)
    return z


@app.post('/api/owner/visits/{vid}/status')
def visit_status(vid: str, x: StatusUpdate, _: dict = Depends(owner)):
    d = load()
    z = next((q for q in d['visits'] if q['id'] == vid), None)
    if not z:
        raise HTTPException(404, 'Visit not found')
    allowed = {'Pending', 'Confirmed', 'Rescheduled', 'Completed', 'Cancelled'}
    if x.status not in allowed:
        raise HTTPException(400, 'Invalid visit status')
    z['status'] = x.status
    z['updated_at'] = now()
    audit(d, 'visit.status_updated', {'id': vid, 'status': x.status})
    save(d)
    return z


@app.post('/api/owner/notifications/read')
def notifications_read(_: dict = Depends(owner)):
    d = load()
    for n in d['notifications']:
        n['read'] = True
    save(d)
    return {'ok': True}


@app.delete('/api/owner/leads/{lid}')
def delete_lead(lid: str, _: dict = Depends(owner)):
    d = load()
    before = len(d['leads'])
    d['leads'] = [x for x in d['leads'] if x['id'] != lid]
    if len(d['leads']) == before:
        raise HTTPException(404, 'Lead not found')
    audit(d, 'lead.deleted', {'id': lid})
    save(d)
    return {'ok': True}


@app.delete('/api/owner/visits/{vid}')
def delete_visit(vid: str, _: dict = Depends(owner)):
    d = load()
    before = len(d['visits'])
    d['visits'] = [x for x in d['visits'] if x['id'] != vid]
    if len(d['visits']) == before:
        raise HTTPException(404, 'Visit not found')
    audit(d, 'visit.deleted', {'id': vid})
    save(d)
    return {'ok': True}


@app.delete('/api/owner/customers/{cid}')
def delete_customer(cid: str, _: dict = Depends(owner)):
    d = load()
    before = len(d['customers'])
    d['customers'] = [x for x in d['customers'] if x.get('id') != cid]
    if len(d['customers']) == before:
        raise HTTPException(404, 'Customer not found')
    for collection in ('leads', 'visits', 'messages'):
        for item in d[collection]:
            if item.get('customer_id') == cid:
                item['customer_id'] = ''
    audit(d, 'customer.deleted', {'id': cid})
    save(d)
    return {'ok': True}


@app.post('/api/owner/customers/bulk-delete')
def bulk_customer_delete(x: BulkPropertyAction, _: dict = Depends(owner)):
    if x.action!='delete': raise HTTPException(400,'Invalid bulk customer action')
    ids=set(x.ids); d=load(); changed=0
    for c in d['customers']:
        if c.get('id') in ids and not c.get('deleted_at'):
            c['deleted_at']=now(); c['updated_at']=now(); c['email']='deleted+'+c['id']+'@invalid.local'; c['name']='Deleted customer'; c['phone']=''; c['saved']=[]; c.pop('password_hash',None); changed+=1
    for collection in ('leads','visits','messages'):
        for item in d[collection]:
            if item.get('customer_id') in ids: item['customer_id']=''; item['updated_at']=now()
    audit(d,'customers.bulk_deleted',{'count':changed}); save(d); return {'ok':True,'changed':changed}


@app.delete('/api/owner/chats/{mid}')
def delete_chat(mid: str, _: dict = Depends(owner)):
    d = load()
    before = len(d['messages'])
    d['messages'] = [x for x in d['messages'] if x['id'] != mid]
    if len(d['messages']) == before:
        raise HTTPException(404, 'Chat not found')
    removed = [x for x in d['messages'] if x['id'] == mid]
    for item in removed:
        sid = item.get('session_id')
        if sid:
            with _SESSION_LOCK:
                _SESSION_CACHE.pop(sid, None)
    audit(d, 'chat.deleted', {'id': mid})
    save(d)
    return {'ok': True}


@app.post('/api/owner/clear/{kind}')
def clear_collection(kind: str, _: dict = Depends(owner)):
    allowed = {'leads', 'visits', 'customers', 'messages'}
    if kind not in allowed:
        raise HTTPException(400, 'Invalid collection')
    d = load()
    count = len(d[kind])
    if kind == 'customers':
        ids = {x.get('id') for x in d['customers']}
        for collection in ('leads', 'visits', 'messages'):
            for item in d[collection]:
                if item.get('customer_id') in ids:
                    item['customer_id'] = ''
    d[kind] = []
    if kind == 'messages':
        with _SESSION_LOCK:
            _SESSION_CACHE.clear()
    audit(d, 'collection.cleared', {'kind': kind, 'count': count})
    save(d)
    return {'ok': True, 'cleared': count}


@app.get('/api/owner/export')
def owner_export(_: dict = Depends(owner)):
    d = load()
    safe = json.loads(json.dumps(d))
    for c in safe['customers']:
        c.pop('password_hash', None)
    return safe


@app.get('/api/owner')
def owner_page(_: dict = Depends(owner)):
    return {'ok': True}
