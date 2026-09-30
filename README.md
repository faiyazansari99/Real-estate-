# EstateAI — Premium AI Real Estate Sales Platform

A single-codebase real-estate website with a public customer experience and a private owner control center.

## Included

### Customer experience
- Premium responsive real-estate website
- Public property browsing and detail pages
- Search by natural text, location, property type, BHK and max price
- Customer signup/login
- Saved properties and private activity history
- Property enquiry and site-visit booking flows
- Direct Call and WhatsApp buttons driven by owner settings
- Floating AI property advisor
- Optional property-image attachment in the AI chat

### AI sales assistant
- Groq API integration through environment variables
- Separate text and vision model configuration
- Natural-language property search and conversation
- Uses only published property data + public business settings
- Dynamic owner call/WhatsApp contact information
- General real-estate guidance when configured
- Guides customers to enquiry, call, WhatsApp and site visit
- Stores website chatbot conversations for owner review
- Does not expose unpublished listings or private owner dashboard data
- Instructed not to invent price, availability, location, legal facts or owner data

### Owner control center
- Separate owner login
- Dashboard overview and analytics
- Add/edit/delete properties
- Publish/unpublish properties
- Full property fields: purpose, type, price, BHK, bathrooms, areas, floors, address, locality, city, state, pincode, map URL, facing, furnishing, parking, construction year, RERA, amenities and description
- Multiple property image uploads
- Leads and enquiry pipeline
- Lead status management
- Customer account list
- Full private AI conversation history
- Site-visit management + status
- Analytics: views, searches, calls, WhatsApp clicks, enquiries, visits and chats
- Owner settings for business name, public contact details, WhatsApp, call number, hours, address, branding and AI business context
- JSON data export
- Audit log
- Demo-listing removal before client launch

## Production architecture

- FastAPI backend
- PostgreSQL persistence when `DATABASE_URL` is configured
- Cloudinary property-image storage when `CLOUDINARY_URL` is configured
- Signed HttpOnly role cookies
- Argon2 customer password hashing
- Optional Argon2 owner password hash support
- Basic application rate limiting for authentication and AI chat
- Vercel-compatible single-entry deployment

For production, configure PostgreSQL and Cloudinary. The local JSON store remains available for offline/demo testing, but it should not be used for a real Vercel production deployment.

## Environment variables

Copy `.env.example` into your deployment settings and fill in real values:

```env
GROQ_API_KEY=
GROQ_TEXT_MODEL=openai/gpt-oss-120b
GROQ_VISION_MODEL=qwen/qwen3.8-27b
JWT_SECRET=replace-with-a-long-random-secret-at-least-32-characters
OWNER_USERNAME=owner
OWNER_PASSWORD=replace-with-a-strong-unique-password
SESSION_DAYS=365
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
CLOUDINARY_URL=cloudinary://API_KEY:API_SECRET@CLOUD_NAME
MAX_UPLOAD_MB=2
MAX_PROPERTY_IMAGES=20
ALLOW_LOCAL_IMAGE_FALLBACK=false
SECURE_COOKIE=true
COOKIE_SAMESITE=lax
ALLOWED_ORIGINS=
RATE_LIMIT_PER_MINUTE=30
```

`JWT_SECRET`, `OWNER_PASSWORD`, and `DATABASE_URL` are required for production. `GROQ_API_KEY` is required for live AI answers; without it the app uses a deterministic fallback for demo/testing. `CLOUDINARY_URL` should be configured before real property images are uploaded.

If `OWNER_PASSWORD` begins with `$argon2`, the backend verifies it as an Argon2 hash; otherwise it is treated as a strong deployment secret and compared securely.

## Local run

```bash
pip install -r requirements.txt
uvicorn index:app --reload
```

Open the local URL shown by Uvicorn.

## Vercel

The repository uses the root `index.py` entry point and `vercel.json` routes both the website and `/api/*` requests to the same FastAPI application.

Add the production environment variables in Vercel Project Settings → Environment Variables. Do not upload `.env` or real secrets to GitHub.

## Client launch checklist

1. Set a strong `OWNER_USERNAME` and `OWNER_PASSWORD`.
2. Generate a random `JWT_SECRET` of at least 32 characters.
3. Connect a PostgreSQL database and set `DATABASE_URL`.
4. Connect Cloudinary and set `CLOUDINARY_URL`.
5. Set `GROQ_API_KEY` and verify the configured text/vision models.
6. Keep `SECURE_COOKIE=true` on HTTPS.
7. Log in as owner and replace demo listings with verified client data.
8. Add the owner's real call and WhatsApp numbers in Owner Settings.
9. Test customer signup/login, enquiry, site visit, AI chat, image attachment and owner history before handing over the site.
10. Never publish unverified property claims, prices, availability or legal information.
