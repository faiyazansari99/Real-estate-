import os, json, uuid, hmac, hashlib, base64, re, copy, threading, contextvars
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import requests
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Request
from fastapi.responses import FileResponse, JSONResponse
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
DB.parent.mkdir(exist_ok=True)

JWT_SECRET = os.getenv('JWT_SECRET', '').strip()
OWNER_USER = os.getenv('OWNER_USERNAME', 'owner').strip()
OWNER_PASS = os.getenv('OWNER_PASSWORD', '').strip()
COOKIE = 'estate_session'
CUSTOMER_COOKIE = 'estate_customer'
CHAT_COOKIE = 'estate_chat'
SESSION_DAYS = int(os.getenv('SESSION_DAYS', '30'))
MAX_UPLOAD_MB = int(os.getenv('MAX_UPLOAD_MB', '2'))
CLOUDINARY_URL = os.getenv('CLOUDINARY_URL', '').strip()
MAX_PROPERTY_IMAGES = int(os.getenv('MAX_PROPERTY_IMAGES', '20'))
MAX_IMAGE_BYTES = MAX_UPLOAD_MB * 1024 * 1024

_PG_CONN = contextvars.ContextVar('pg_conn', default=None)
_PG_POOL = None
_PG_POOL_LOCK = threading.Lock()

def _pg_url():
    return DATABASE_URL.replace('postgres://', 'postgresql://', 1) if DATABASE_URL else ''

def _pg_pool():
    global _PG_POOL
    if not DATABASE_URL:
        return None
    if _PG_POOL is None:
        with _PG_POOL_LOCK:
            if _PG_POOL is None:
                _PG_POOL = ConnectionPool(conninfo=_pg_url(), min_size=1, max_size=int(os.getenv('DB_POOL_MAX_SIZE', '10')), open=True, timeout=10)
                with _PG_POOL.connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("CREATE TABLE IF NOT EXISTS estate_state (id INTEGER PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
                    conn.commit()
    return _PG_POOL

def _pg_connect():
    pool = _pg_pool()
    if pool is None:
        return None
    return pool.getconn()

def _pg_request_conn():
    return _PG_CONN.get()

SECURE_COOKIE = os.getenv('SECURE_COOKIE', 'false').lower() == 'true'
COOKIE_SAMESITE = os.getenv('COOKIE_SAMESITE', 'lax').lower()
if COOKIE_SAMESITE not in {'lax', 'strict', 'none'}:
    COOKIE_SAMESITE = 'lax'

if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError('JWT_SECRET must be configured and at least 32 characters long')
if not OWNER_PASS:
    raise RuntimeError('OWNER_PASSWORD must be configured before starting the application')

ph = PasswordHasher()
_SESSION_CACHE = {}
_SESSION_TTL_SECONDS = int(os.getenv('SESSION_CACHE_TTL_SECONDS', '3600'))
_SESSION_LOCK = threading.Lock()
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
    if DATABASE_URL and conn is not None:
        with conn.cursor() as cur:
            cur.execute('SELECT data FROM estate_state WHERE id=1')
            row = cur.fetchone()
            if row is None:
                d = copy.deepcopy(DEFAULT)
                cur.execute('INSERT INTO estate_state (id, data) VALUES (1, %s)', (json.dumps(d, ensure_ascii=False),))
                return d
            return _merge_defaults(row[0])
    if DATABASE_URL:
        pool = _pg_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT data FROM estate_state WHERE id=1')
                row = cur.fetchone()
                if row is None:
                    d = copy.deepcopy(DEFAULT)
                    cur.execute('INSERT INTO estate_state (id, data) VALUES (1, %s)', (json.dumps(d, ensure_ascii=False),))
                    conn.commit()
                    return d
                d = _merge_defaults(row[0])
                conn.commit()
                return d
    if not DB.exists():
        save(copy.deepcopy(DEFAULT))
    try:
        return _merge_defaults(json.loads(DB.read_text(encoding='utf-8')))
    except Exception:
        save(copy.deepcopy(DEFAULT))
        return json.loads(DB.read_text(encoding='utf-8'))


def save(d):
    conn = _pg_request_conn()
    if DATABASE_URL and conn is not None:
        with conn.cursor() as cur:
            cur.execute('UPDATE estate_state SET data=%s, updated_at=NOW() WHERE id=1', (json.dumps(d, ensure_ascii=False),))
            if cur.rowcount == 0:
                cur.execute('INSERT INTO estate_state (id, data) VALUES (1, %s)', (json.dumps(d, ensure_ascii=False),))
        return
    if DATABASE_URL:
        pool = _pg_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE estate_state SET data=%s, updated_at=NOW() WHERE id=1', (json.dumps(d, ensure_ascii=False),))
                if cur.rowcount == 0:
                    cur.execute('INSERT INTO estate_state (id, data) VALUES (1, %s)', (json.dumps(d, ensure_ascii=False),))
            conn.commit()
        return
    tmp = DB.with_suffix('.tmp')
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp.replace(DB)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        if password_hash.startswith('$argon2'):
            return ph.verify(password_hash, password)
        if re.fullmatch(r'[0-9a-f]{64}', password_hash or ''):
            return hmac.compare_digest(password_hash, hashlib.sha256(password.encode()).hexdigest())
        return False
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def get_session_history(d, session_id, limit=8):
    now_ts = __import__('time').time()
    with _SESSION_LOCK:
        cached = _SESSION_CACHE.get(session_id)
        if cached is not None:
            ts, items = cached
            if now_ts - ts <= _SESSION_TTL_SECONDS:
                _SESSION_CACHE[session_id] = (now_ts, items)
                return items[-limit:]
            _SESSION_CACHE.pop(session_id, None)
    hist = [m for m in d['messages'] if m.get('session_id') == session_id][-limit:]
    with _SESSION_LOCK:
        _SESSION_CACHE[session_id] = (now_ts, hist[-20:])
        return hist[-limit:]


def append_session_message(session_id, item):
    with _SESSION_LOCK:
        now_ts = __import__('time').time()
        cached = _SESSION_CACHE.get(session_id)
        hist = list(cached[1]) if cached and now_ts - cached[0] <= _SESSION_TTL_SECONDS else []
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


def public_props(d):
    out = []
    for p in d['properties']:
        if p.get('published') and p.get('status', '') not in ['Draft', 'Archived']:
            item = copy.deepcopy(p)
            item.pop('is_demo', None)
            out.append(item)
    return out


def normalize_phone(v):
    return re.sub(r'[^0-9+]', '', v or '')


def whatsapp_url(v):
    n = normalize_phone(v).replace('+', '')
    return 'https://wa.me/' + n if n else ''


def make_token(user, role, days=1):
    payload = {'u': user, 'role': role, 'exp': int(datetime.now(timezone.utc).timestamp()) + days * 86400}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
    sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return body + '.' + base64.urlsafe_b64encode(sig).decode().rstrip('=')


def verify(t, role=None):
    try:
        body, s = t.split('.', 1)
        sig = base64.urlsafe_b64decode(s + '==')
        good = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good):
            return None
        p = json.loads(base64.urlsafe_b64decode(body + '=='))
        if p.get('exp', 0) <= int(datetime.now(timezone.utc).timestamp()):
            return None
        if role and p.get('role') != role:
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


def chat_session(request: Request, requested: str = ''):
    if requested and re.fullmatch(r's_[A-Za-z0-9_-]{20,100}', requested):
        return requested, requested != request.cookies.get(CHAT_COOKIE, '')
    token = request.cookies.get(CHAT_COOKIE, '')
    if token and re.fullmatch(r's_[A-Za-z0-9_-]{20,100}', token):
        return token, False
    sid = 's_' + uuid.uuid4().hex
    return sid, True


def groq(messages, model=None, image_data=None):
    key = os.getenv('GROQ_API_KEY', '').strip()
    if not key:
        return None
    model = model or os.getenv('GROQ_TEXT_MODEL', 'openai/gpt-oss-120b')
    if image_data:
        messages = [dict(m) for m in messages]
        last = messages[-1]
        content = [{'type': 'text', 'text': last.get('content', '')}, {'type': 'image_url', 'image_url': {'url': image_data}}]
        messages[-1] = {**last, 'content': content}
    try:
        r = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'},
            json={'model': model, 'messages': messages, 'temperature': 0.25, 'max_completion_tokens': 1400},
            timeout=35
        )
        if r.ok:
            return r.json()['choices'][0]['message']['content']
    except Exception:
        pass
    return None


app = FastAPI(title='EstateAI - Premium AI Real Estate Sales Platform', version='4.0.0')

@app.middleware('http')
async def persistence_middleware(request: Request, call_next):
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'} and request.url.path.startswith('/api/'):
        import time
        key = request.client.host if request.client else 'unknown'
        bucket = request.method + ':' + request.url.path + ':' + key
        now_ts = time.time()
        with _RATE_LOCK:
            recent = [t for t in _RATE_CACHE.get(bucket, []) if now_ts - t < 60]
            if len(recent) >= int(os.getenv('RATE_LIMIT_PER_MINUTE', '30')):
                return JSONResponse({'detail': 'Too many requests. Please try again shortly.'}, status_code=429, headers={'Retry-After': '60'})
            recent.append(now_ts)
            _RATE_CACHE[bucket] = recent
            if len(_RATE_CACHE) > 10000:
                stale = [k for k, vals in _RATE_CACHE.items() if not vals or now_ts - vals[-1] > 300]
                for k in stale[:5000]:
                    _RATE_CACHE.pop(k, None)
    if not DATABASE_URL or request.method in {'GET', 'HEAD', 'OPTIONS'}:
        return await call_next(request)
    pool = _pg_pool()
    with pool.connection() as conn:
        token = _PG_CONN.set(conn)
        try:
            with conn.cursor() as cur:
                cur.execute('SELECT pg_advisory_xact_lock(73421901)')
            response = await call_next(request)
            conn.commit()
            return response
        except Exception:
            conn.rollback()
            raise
        finally:
            _PG_CONN.reset(token)

ALLOWED_ORIGINS = [o.strip() for o in os.getenv('ALLOWED_ORIGINS', '').split(',') if o.strip()]
if ALLOWED_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=['*'], allow_headers=['*'], allow_credentials=True)


class Login(BaseModel):
    username: str
    password: str
    remember: bool = False


class CustomerSignup(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    phone: str = Field(min_length=5, max_length=30)
    password: str = Field(min_length=8, max_length=128)

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
    message: str = Field(min_length=1, max_length=4000)
    session_id: str = 'public'
    property_id: str = ''
    image_data: str = Field(default='', max_length=5_000_000)


class Lead(BaseModel):
    name: str = Field(min_length=2)
    phone: str = Field(min_length=5)
    email: str = ''
    budget: str = ''
    location: str = ''
    bhk: str = ''
    property_id: str = ''
    source: str = 'Website'
    consent: bool = True
    customer_id: str = ''

class Visit(BaseModel):
    name: str = Field(min_length=2)
    phone: str = Field(min_length=5)
    email: str = ''
    date: str
    time: str
    property_id: str = ''
    notes: str = ''
    consent: bool = True
    customer_id: str = ''

    @field_validator('date')
    @classmethod
    def validate_date(cls, v):
        try:
            d = datetime.strptime(v, '%Y-%m-%d').date()
        except ValueError:
            raise ValueError('Date must be YYYY-MM-DD')
        if d < datetime.now(timezone.utc).date():
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
    brand: str = 'EstateAI'
    tagline: str = ''
    owner_name: str = ''
    owner_email: str = ''
    phone: str = ''
    whatsapp: str = ''
    currency: str = '₹'
    ai_greeting: str = ''
    business_hours: str = ''
    about: str = ''
    address: str = ''
    logo_url: str = ''
    hero_image: str = ''
    ai_business_context: str = ''


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
    phone: str = ''
    email: str = ''


@app.get('/')
def home():
    return FileResponse(ROOT / 'index.html')


@app.get('/api/health')
def health():
    return {'ok': True, 'version': app.version, 'time': now(), 'storage': 'postgresql' if DATABASE_URL else 'local-json', 'image_storage': 'cloudinary' if CLOUDINARY_URL else 'local-fallback'}


# ---------- Auth ----------
@app.post('/api/auth/login')
def owner_login(x: Login):
    password_ok = False
    if OWNER_PASS.startswith('$argon2'):
        try:
            password_ok = ph.verify(OWNER_PASS, x.password)
        except Exception:
            password_ok = False
    else:
        password_ok = hmac.compare_digest(x.password, OWNER_PASS)
    if x.username != OWNER_USER or not password_ok:
        raise HTTPException(401, 'Invalid owner username or password')
    t = make_token(x.username, 'owner', SESSION_DAYS if x.remember else 1)
    r = JSONResponse({'ok': True, 'role': 'owner', 'username': x.username})
    r.set_cookie(COOKIE, t, max_age=SESSION_DAYS * 86400 if x.remember else None, httponly=True, secure=SECURE_COOKIE, samesite=COOKIE_SAMESITE, path='/')
    d = load()
    audit(d, 'auth.owner_login', {'username': x.username})
    save(d)
    return r


@app.post('/api/auth/logout')
def logout():
    r = JSONResponse({'ok': True})
    r.delete_cookie(COOKIE, path='/')
    r.delete_cookie(CUSTOMER_COOKIE, path='/')
    return r


@app.get('/api/auth/me')
def me(request: Request):
    o = verify(request.cookies.get(COOKIE, ''), 'owner')
    c = verify(request.cookies.get(CUSTOMER_COOKIE, ''), 'customer')
    d = load()
    cust = next((x for x in d['customers'] if x['id'] == c.get('id')), None) if c else None
    return {'authenticated': bool(o or c), 'role': 'owner' if o else ('customer' if c else None), 'username': o.get('u') if o else None, 'customer': cust}


@app.post('/api/customer/signup')
def customer_signup(x: CustomerSignup):
    d = load()
    if any(c.get('email', '').lower() == x.email.lower() for c in d['customers']):
        raise HTTPException(409, 'An account with this email already exists')
    c = {'id': uid('c_'), 'name': x.name, 'email': x.email, 'phone': x.phone, 'password_hash': hash_password(x.password), 'saved': [], 'created_at': now()}
    d['customers'].insert(0, c)
    audit(d, 'customer.signup', {'id': c['id']})
    save(d)
    r = JSONResponse({'ok': True, 'customer': {k: v for k, v in c.items() if k != 'password_hash'}})
    r.set_cookie(CUSTOMER_COOKIE, make_token(c['id'], 'customer', SESSION_DAYS), max_age=SESSION_DAYS * 86400, httponly=True, secure=SECURE_COOKIE, samesite=COOKIE_SAMESITE, path='/')
    return r


@app.post('/api/customer/login')
def customer_login(x: CustomerLogin):
    d = load()
    c = next((z for z in d['customers'] if z.get('email', '').lower() == x.email.lower()), None)
    if not c or not verify_password(c.get('password_hash', ''), x.password):
        raise HTTPException(401, 'Invalid customer login')
    if re.fullmatch(r'[0-9a-f]{64}', c.get('password_hash', '') or ''):
        c['password_hash'] = hash_password(x.password)
        save(d)
    r = JSONResponse({'ok': True, 'customer': {k: v for k, v in c.items() if k != 'password_hash'}})
    r.set_cookie(CUSTOMER_COOKIE, make_token(c['id'], 'customer', SESSION_DAYS), max_age=SESSION_DAYS * 86400, httponly=True, secure=SECURE_COOKIE, samesite=COOKIE_SAMESITE, path='/')
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
    xdata = x.model_dump()
    xdata['email'] = new_email
    z.update(xdata)
    audit(d, 'customer.profile_updated', {'id': z['id']})
    save(d)
    return {k: v for k, v in z.items() if k != 'password_hash'}


# ---------- Public data ----------
@app.get('/api/settings')
def settings():
    s = load()['settings']
    return {k: v for k, v in s.items() if k not in ['ai_business_context']}


@app.get('/api/properties')
def properties(q: str = '', location: str = '', ptype: str = '', purpose: str = '', bhk: str = '', min_price: float = 0, max_price: float = 0):
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
    return arr


@app.get('/api/properties/{pid}')
def property_detail(pid: str):
    d = load()
    p = next((x for x in public_props(d) if x['id'] == pid), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    p['views'] = p.get('views', 0) + 1
    d['metrics']['property_views'] += 1
    audit(d, 'property.viewed', {'id': pid})
    save(d)
    return p


@app.post('/api/events/{kind}')
def event(kind: str):
    d = load()
    key = {'call': 'calls', 'whatsapp': 'whatsapp', 'search': 'searches'}.get(kind)
    if key:
        d['metrics'][key] = d['metrics'].get(key, 0) + 1
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
    item = {'id': uid('lead_'), **l.model_dump(), 'customer_id': cid, 'status': 'New', 'score': 'Warm', 'created_at': now()}
    d['leads'].insert(0, item)
    d['notifications'].insert(0, {'id': uid('n_'), 'type': 'lead', 'title': 'New customer lead', 'text': l.name + ' submitted an enquiry', 'at': now(), 'read': False})
    d['metrics']['enquiries'] += 1
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
    item = {'id': uid('visit_'), **v.model_dump(), 'customer_id': cid, 'status': 'Pending', 'created_at': now()}
    d['visits'].insert(0, item)
    d['notifications'].insert(0, {'id': uid('n_'), 'type': 'visit', 'title': 'New site-visit request', 'text': v.name + ' requested a visit', 'at': now(), 'read': False})
    d['metrics']['bookings'] += 1
    audit(d, 'visit.created', {'visit_id': item['id']})
    save(d)
    return {'ok': True, 'visit': item, 'message': 'Request submitted. The property team will confirm the visit.'}


# ---------- AI ----------
@app.post('/api/chat')
def chat(c: Chat, request: Request):
    d = load()
    cust = optional_customer(request)
    published = public_props(d)
    sid, created_chat_cookie = chat_session(request, c.session_id)
    msg = c.message.strip()
    low = msg.lower()

    candidates = []
    for p in published:
        blob = json.dumps(p, ensure_ascii=False).lower()
        score = 0
        for term in re.findall(r'[a-z0-9]+', low):
            if len(term) > 2 and term in blob:
                score += 1
        if score:
            candidates.append((score, p))
    candidates = [p for _, p in sorted(candidates, key=lambda x: x[0], reverse=True)[:8]]

    context = '\n'.join([
        'ID:' + p['id'] + ' | ' + str(p.get('title', '')) + ' | ' + str(p.get('purpose', '')) + ' | ' + str(p.get('type', '')) + ' | ' + str(p.get('bhk', '')) + ' | Rs ' + str(p.get('price', '')) + ' | ' + str(p.get('location', '')) + ' | ' + str(p.get('area', '')) + ' | ' + str(p.get('status', '')) + ' | Amenities: ' + ', '.join(p.get('amenities', []))
        for p in (candidates or published[:12])
    ])

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

    history = get_session_history(d, sid, limit=8)
    messages = [{'role': 'system', 'content': system}]
    for h in history:
        messages += [{'role': 'user', 'content': h['user']}, {'role': 'assistant', 'content': h['assistant']}]
    messages.append({'role': 'user', 'content': msg})

    answer = groq(messages, model=(os.getenv('GROQ_VISION_MODEL', 'qwen/qwen3.8-27b') if c.image_data else os.getenv('GROQ_TEXT_MODEL', 'openai/gpt-oss-120b')), image_data=(c.image_data if c.image_data.startswith('data:image/') else None))
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
def owner_data(_: dict = Depends(owner)):
    d = load()
    return {k: d[k] for k in ['settings', 'properties', 'customers', 'leads', 'visits', 'messages', 'notifications', 'audit', 'metrics']}


@app.post('/api/settings')
def update_settings(s: Settings, _: dict = Depends(owner)):
    d = load()
    d['settings'] = s.model_dump()
    audit(d, 'settings.updated')
    save(d)
    return d['settings']


@app.post('/api/properties')
def add_property(p: dict, _: dict = Depends(owner)):
    d = load()
    p = dict(p)
    p['id'] = uid('p_')
    p.setdefault('published', False)
    p.setdefault('views', 0)
    p.setdefault('images', [])
    p.setdefault('created_at', now())
    p.setdefault('updated_at', now())
    d['properties'].insert(0, p)
    audit(d, 'property.created', {'id': p['id']})
    save(d)
    return p


@app.put('/api/properties/{pid}')
def edit_property(pid: str, p: dict, _: dict = Depends(owner)):
    d = load()
    old = next((x for x in d['properties'] if x['id'] == pid), None)
    if not old:
        raise HTTPException(404, 'Property not found')
    p = dict(p)
    p['id'] = pid
    p['images'] = p.get('images', old.get('images', []))
    p['views'] = old.get('views', 0)
    p['created_at'] = old.get('created_at', now())
    p['updated_at'] = now()
    d['properties'][d['properties'].index(old)] = p
    audit(d, 'property.updated', {'id': pid})
    save(d)
    return p


@app.delete('/api/properties/{pid}')
def delete_property(pid: str, _: dict = Depends(owner)):
    d = load()
    before = len(d['properties'])
    d['properties'] = [p for p in d['properties'] if p['id'] != pid]
    if len(d['properties']) == before:
        raise HTTPException(404, 'Property not found')
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


@app.post('/api/properties/{pid}/images')
async def image_upload(pid: str, file: UploadFile = File(...), _: dict = Depends(owner)):
    d = load()
    p = next((x for x in d['properties'] if x['id'] == pid), None)
    if not p:
        raise HTTPException(404, 'Property not found')
    if not (file.content_type or '').startswith('image/'):
        raise HTTPException(400, 'Only image files are allowed')
    if len(p.get('images', [])) >= MAX_PROPERTY_IMAGES:
        raise HTTPException(400, 'Maximum image limit reached for this property')
    raw = await file.read()
    if len(raw) > MAX_IMAGE_BYTES:
        raise HTTPException(413, 'Max image size is ' + str(MAX_UPLOAD_MB) + ' MB')
    image = {'id': uid('img_'), 'name': file.filename, 'url': '', 'data': '', 'public_id': ''}
    if CLOUDINARY_URL:
        try:
            import cloudinary
            import cloudinary.uploader
            cloudinary.config(cloudinary_url=CLOUDINARY_URL)
            result = cloudinary.uploader.upload(raw, folder='estateai/properties', resource_type='image', public_id=Path(file.filename or 'image').stem + '_' + uuid.uuid4().hex[:8])
            image['url'] = result.get('secure_url', '')
            image['public_id'] = result.get('public_id', '')
        except ImportError:
            image['data'] = 'data:' + file.content_type + ';base64,' + base64.b64encode(raw).decode()
        except Exception as e:
            raise HTTPException(502, 'Image storage upload failed: ' + str(e))
    else:
        if os.getenv('ALLOW_LOCAL_IMAGE_FALLBACK', 'true').lower() != 'true':
            raise HTTPException(503, 'Image storage is not configured. Set CLOUDINARY_URL before uploading images.')
        image['data'] = 'data:' + file.content_type + ';base64,' + base64.b64encode(raw).decode()
    p.setdefault('images', []).append(image)
    audit(d, 'property.image_uploaded', {'property_id': pid, 'name': file.filename})
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
        except Exception:
            # Database removal still succeeds; an orphaned remote asset can be cleaned separately.
            pass
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
    z['status'] = x.status
    audit(d, 'lead.status_updated', {'id': lid, 'status': x.status})
    save(d)
    return z


@app.post('/api/owner/visits/{vid}/status')
def visit_status(vid: str, x: StatusUpdate, _: dict = Depends(owner)):
    d = load()
    z = next((q for q in d['visits'] if q['id'] == vid), None)
    if not z:
        raise HTTPException(404, 'Visit not found')
    z['status'] = x.status
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
    d['customers'] = [x for x in d['customers'] if x['id'] != cid]
    if len(d['customers']) == before:
        raise HTTPException(404, 'Customer not found')
    audit(d, 'customer.deleted', {'id': cid})
    save(d)
    return {'ok': True}


@app.delete('/api/owner/chats/{mid}')
def delete_chat(mid: str, _: dict = Depends(owner)):
    d = load()
    before = len(d['messages'])
    d['messages'] = [x for x in d['messages'] if x['id'] != mid]
    if len(d['messages']) == before:
        raise HTTPException(404, 'Chat not found')
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
    d[kind] = []
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
