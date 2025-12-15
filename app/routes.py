from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response, make_response
import csv
import io
import os
import base64
# import json  <--- VERWIJDERD
import uuid
import traceback
from datetime import datetime, date
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from supabase import create_client
import requests
from openpyxl import Workbook
from openpyxl.drawing.image import Image as XLImage
from openpyxl.worksheet.table import Table, TableStyleInfo
import re
from .category_suggester import (
    suggest_probleemcategorie,
    suggest_probleemcategorie_contextual_sqlalchemy,
)
from .models import Businessunit, Klant, Probleemcategorie, db, klacht_status_enum

main = Blueprint('main', __name__)

# Supabase configuratie
supabase_url = "https://kilpcevxhcwysfllheen.supabase.co"
supabase_key = "sb_secret_Ft6fDkZhNVImBd_cgxFWZg_lCXrcbUa"
supabase = create_client(supabase_url, supabase_key)

# NIEUW: naam van je Storage bucket
BUCKET_NAME = "bijlages"

# Toggle: bestanden in DB opslaan i.p.v. Storage (let op: base64 in DB kan groot worden)
# Dit staat nu permanent op False, Base64/DB-opslag is uit de functies verwijderd.
STORE_FILES_IN_DB = False  # alleen Storage gebruiken


@main.route('/')
def index():
    return redirect(url_for('main.login'))

@main.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		email = request.form.get('email')
		password = request.form.get('password')
		
		if not email or not password:
			flash('Vul alle velden in', 'error')
			return render_template('login.html')
		
		try:
			# Zoek gebruiker in de 'gebruiker' tabel
			response = supabase.table("gebruiker").select("*").eq("email", email).execute()
			
			if response.data and len(response.data) > 0:
				user_data = response.data[0]
				stored_password = user_data.get('wachtwoord')

				if stored_password and check_password_hash(stored_password, password):
					# Login succesvol
					bu_id = user_data.get('businessunit_id')
					bu_naam = get_businessunit_name(bu_id)
					session['user_id'] = user_data['gebruiker_id']
					session['user_email'] = user_data['email']
					session['user_naam'] = user_data['naam']
					# Normalize role display: Capitalise only first character (e.g., "Key user")
					session['user_rol'] = (user_data.get('rol') or '').strip().capitalize()
					session['businessunit_id'] = bu_id
					session['businessunit_naam'] = bu_naam

					# Redirect naar rol-specifieke dashboard (automatisch)
					flash('Login succesvol!', 'success')
					if session['user_rol'] == 'Admin':
						return redirect(url_for('main.admin_dashboard'))
					elif session['user_rol'] == 'Key user':
						return redirect(url_for('main.keyuser_dashboard'))
					else:
						return redirect(url_for('main.user_dashboard'))

				# Als plain text (voor testing)
				elif stored_password == password:
					bu_id = user_data.get('businessunit_id')
					bu_naam = get_businessunit_name(bu_id)
					session['user_id'] = user_data['gebruiker_id']
					session['user_email'] = user_data['email']
					session['user_naam'] = user_data['naam']
					session['user_rol'] = (user_data.get('rol') or '').strip().capitalize()
					session['businessunit_id'] = bu_id
					session['businessunit_naam'] = bu_naam

					# Redirect naar rol-specifieke dashboard (automatisch)
					flash('Login succesvol!', 'success')
					if session['user_rol'] == 'Admin':
						return redirect(url_for('main.admin_dashboard'))
					elif session['user_rol'] == 'Key user':
						return redirect(url_for('main.keyuser_dashboard'))
					else:
						return redirect(url_for('main.user_dashboard'))
				else:
					flash('Ongeldig wachtwoord', 'error')
			else:
				flash('Gebruiker niet gevonden', 'error')
				
		except Exception as e:
			flash('Er ging iets mis bij het inloggen', 'error')
			print(f"Login error: {e}")
		
		return render_template('login.html')
    
	return render_template('login.html')

@main.route('/logout')
def logout():
    session.clear()
    flash('Je bent uitgelogd', 'info')
    return redirect(url_for('main.login'))

@main.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    role = normalized_role()
    if role == 'Admin':
        return redirect(url_for('main.admin_dashboard'))
    elif role == 'Key user':
        return redirect(url_for('main.keyuser_dashboard'))
    else:
        return render_template('user_dashboard.html')

# Helper: safely cast to int if possible
def safe_int(val):
    try:
        return int(val)
    except Exception:
        return val

# Helper: ensure product exists before inserting a complaint
def ensure_product_exists(artikelnummer, artikelnaam=None):
    if not artikelnummer:
        return None
    artikel_nmr = safe_int(artikelnummer)
    if artikel_nmr is None:
        artikel_nmr = artikelnummer
    try:
        resp = supabase.table("product").select("artikel_nr").eq("artikel_nr", artikel_nmr).limit(1).execute()
        check_supabase_response(resp, "lookup product for klacht")
        if resp.data:
            return artikel_nmr
    except Exception as e:
        print(f"Warning: product lookup failed: {e}")
    try:
        payload = {"artikel_nr": artikel_nmr}
        if artikelnaam:
            payload["naam"] = artikelnaam.strip()
        insert_resp = supabase.table("product").insert(payload).execute()
        check_supabase_response(insert_resp, "insert new product for klacht")
        return artikel_nmr
    except Exception as e:
        print(f"Warning: insert product failed: {e}")
    return artikel_nmr

# Helper: ensure order exists before inserting a complaint
def ensure_order_exists(order_nummer, klant_id=None):
    if not order_nummer:
        return None
    try:
        resp = supabase.table("order").select("order_nummer").eq("order_nummer", order_nummer).limit(1).execute()
        check_supabase_response(resp, "lookup order for klacht")
        if resp.data:
            return order_nummer
    except Exception as e:
        print(f"Warning: order lookup failed: {e}")
    try:
        payload = {"order_nummer": order_nummer}
        if klant_id:
            payload["klant_id"] = safe_int(klant_id)
        insert_resp = supabase.table("order").insert(payload).execute()
        check_supabase_response(insert_resp, "insert new order for klacht")
    except Exception as e:
        print(f"Warning: insert order failed: {e}")
    return order_nummer

# Helper: fetch businessunit naam (new schema)
def get_businessunit_name(bu_id):
    if not bu_id:
        return ''
    try:
        resp = supabase.table("businessunit").select("naam").eq("businessunit_id", safe_int(bu_id)).execute()
        check_supabase_response(resp, "fetch businessunit naam")
        if resp.data and len(resp.data) > 0:
            return resp.data[0].get('naam') or ''
    except Exception as e:
        print(f"Warning: businessunit naam niet gevonden: {e}")
    return ''

# Helper: resolve or create businessunit by id or naam, return id or None
def resolve_or_create_businessunit(value):
    if not value:
        return None
    try:
        return int(value)
    except Exception:
        pass
    naam = str(value).strip()
    if not naam:
        return None
    try:
        resp = supabase.table("businessunit").select("businessunit_id").eq("naam", naam).execute()
        check_supabase_response(resp, "lookup businessunit by naam")
        if resp.data and len(resp.data) > 0:
            return resp.data[0].get('businessunit_id')
        insert_resp = supabase.table("businessunit").insert({"naam": naam}).execute()
        check_supabase_response(insert_resp, "insert businessunit by naam")
        if insert_resp.data and len(insert_resp.data) > 0:
            return insert_resp.data[0].get('businessunit_id')
    except Exception as e:
        print(f"resolve_or_create_businessunit error: {e}")
    return None

# Helper: fetch users by roles (optioneel filter op businessunit)
def get_users_by_roles(roles=None, businessunit=None):
    try:
        roles = roles or []
        if roles:
            resp = supabase.table("gebruiker").select("gebruiker_id, naam, email, rol, businessunit_id").in_("rol", roles).execute()
        else:
            resp = supabase.table("gebruiker").select("gebruiker_id, naam, email, rol, businessunit_id").execute()
        check_supabase_response(resp, "fetch users by roles")
        users = resp.data if resp.data else []
        if businessunit:
            users = [u for u in users if get_businessunit_name(u.get('businessunit_id')) == businessunit]
        return users
    except Exception as e:
        print(f"Warning: get_users_by_roles failed: {e}")
        return []

# Helper: fetch image bytes (from URL or data:) for embedding in Excel
def fetch_image_bytes(url):
    if not url:
        return None
    try:
        if url.startswith('data:'):
            # data URL: data:image/png;base64,... (LEGACY SUPPORT)
            if ';base64,' in url:
                b64 = url.split(';base64,', 1)[1]
                return base64.b64decode(b64)
            return None
        # normal URL
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and resp.headers.get('Content-Type', '').startswith('image/'):
            return resp.content
    except Exception as e:
        print(f"fetch_image_bytes error: {e}")
    return None

# Update check_supabase_response to support raw dict responses and better logging (non-fatal when no error)
def check_supabase_response(resp, ctx=""):
    """Check supabase response for errors and raise if present (or return data)."""
    # Accept string/dict/None/Response etc.
    if resp is None:
        raise Exception(f"Empty response from Supabase at {ctx}")

    # If it's a dict-like response (legacy), allow error handling
    if isinstance(resp, dict):
        err = resp.get('error')
        if err:
            msg = err.get('message') if isinstance(err, dict) else str(err)
            print(f"Supabase error in {ctx}: {msg}")
            raise Exception(f"Supabase error in {ctx}: {msg}")
        return resp

    # If it's an object with .error attribute
    err = getattr(resp, 'error', None)
    if err:
        # try extract message if present
        msg = err.message if hasattr(err, 'message') else repr(err)
        print(f"Supabase error in {ctx}: {msg}")
        raise Exception(f"Supabase error in {ctx}: {msg}")
    return resp

# Helper: fetch businessunit-namen via SQLAlchemy (fallback Supabase)
def get_businessunits_list():
    try:
        rows = db.session.query(Businessunit.naam).order_by(Businessunit.naam).all()
        names = [r[0] for r in rows if r and r[0]]
        if names:
            return names
    except Exception as e:
        print(f"Warning: kon businessunits niet ophalen via SQLAlchemy: {e}")
    try:
        resp = supabase.table("businessunit").select("naam").order("naam").execute()
        check_supabase_response(resp, "fetch businessunits list")
        names = [b.get('naam') for b in (resp.data or []) if b.get('naam')]
        return names
    except Exception as e:
        print(f"Warning: kon businessunits niet ophalen: {e}")
        return []


def get_categorieen_list():
    """Haal categorie_id + type op (SQLAlchemy met Supabase-fallback)."""
    try:
        rows = (
            db.session.query(Probleemcategorie.categorie_id, Probleemcategorie.type)
            .order_by(Probleemcategorie.type)
            .all()
        )
        cats = [
            {"categorie_id": cid, "type": ctype}
            for cid, ctype in rows
            if cid is not None and ctype is not None
        ]
        if cats:
            return cats
    except Exception as e:
        print(f"Warning: kon categorieën niet ophalen via SQLAlchemy: {e}")
    try:
        resp = supabase.table("probleemcategorie").select("categorie_id, type").order("type").execute()
        check_supabase_response(resp, "fetching probleemcategorie")
        return resp.data if resp.data else []
    except Exception as e:
        print(f"Warning: kon categorieën niet ophalen via Supabase: {e}")
        return []


def get_status_options():
    """Alle mogelijke statuswaarden vanuit het model ENUM."""
    try:
        return list(klacht_status_enum.enums)
    except Exception as e:
        print(f"Warning: kon status opties niet ophalen: {e}")
        return []


def suggest_categorie_safe(omschrijving, oorzaak, businessunit_id=None):
    """
    Probeer de contextuele suggestie (ORM) en val terug op de eenvoudige keyword-suggestie
    als de database niet bereikbaar is.
    """
    omschrijving = (omschrijving or "").strip()
    oorzaak = (oorzaak or "").strip()
    if not omschrijving and not oorzaak:
        return "Andere"
    try:
        return suggest_probleemcategorie_contextual_sqlalchemy(
            omschrijving,
            oorzaak,
            businessunit_id=businessunit_id,
        )
    except Exception as e:
        print(f"Warning: suggest_probleemcategorie_contextual_sqlalchemy faalde, fallback naar simpele suggestie: {e}")
        return suggest_probleemcategorie(omschrijving, oorzaak)


def find_categorie_id_by_type(categorieen, categorie_type):
    """Zoek de categorie_id op basis van het type; helper voor autosuggestie."""
    if not categorie_type:
        return None
    for categorie in categorieen or []:
        cat_type = (categorie.get('type') or '').strip().lower()
        if cat_type == str(categorie_type).strip().lower():
            return categorie.get('categorie_id')
    return None

# Helper: normalize businessunit from complaint row
def get_bu_value(obj):
    if not obj:
        return ''
    if obj.get('businessunit'):
        return str(obj.get('businessunit')).strip()
    try:
        bu_id = obj.get('businessunit_id')
        if bu_id:
            return (get_businessunit_name(bu_id) or '').strip()
    except Exception:
        return ''
    return ''

def is_klacht_today(klacht, today_str=None):
    """Check if a complaint was created/entered today using multiple possible date fields."""
    today_str = today_str or date.today().isoformat()
    dm = str(
        klacht.get('datum_melding')
        or klacht.get('created_at')
        or klacht.get('created')
        or klacht.get('datum')
        or ''
    )
    return dm[:10] == today_str

# NIEUW: Normalizeert de DB-string van URL's naar de structuur die de template verwacht.
def normalize_bijlages(raw_bijlages):
    """
    Converteert de opgeslagen waarde (TEXT met newline-gescheiden URL's)
    naar een lijst van dicts voor de template, met LEGACY FALLBACK voor oude JSON/dicts.
    """
    if not raw_bijlages:
        return []
    
    urls = []
    
    # 1. Behandel de moderne opgeslagen string (newline-gescheiden URL's)
    if isinstance(raw_bijlages, str):
        urls.extend([u.strip() for u in raw_bijlages.splitlines() if u.strip()])
    
    # 2. Behandel de oude opgeslagen Lijst-van-objects format (LEGACY FALLBACK)
    elif isinstance(raw_bijlages, list):
        for b in raw_bijlages:
            if isinstance(b, dict) and b.get("url"):
                urls.append(b["url"])
            elif isinstance(b, str):
                urls.append(b)
                
    # 3. Filter op unieke, geldige URL-strings en converteer naar template-dicts
    normalized = []
    unique_urls = set()
    for url in urls:
        if url in unique_urls:
            continue
        unique_urls.add(url)
        
        url_lower = url.lower()
        # De is_image check is belangrijk voor de template en Excel export
        is_img = url.startswith('data:image') or url_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))
        
        normalized.append({
            "id": str(uuid.uuid4()),
            "url": url,
            "naam": url.split("/")[-1] if "/" in url else url,
            "is_image": is_img
        })
        
    return normalized

# NIEUW: Slaat de bijlages op als een newline-gescheiden string van URL's.
def serialize_bijlages_for_db(bijlage_list):
    """Sla op als newline-gescheiden URL's (eenvoudige TEXT-opslag)."""
    if not bijlage_list:
        return None
    try:
        urls = []
        for b in bijlage_list:
            # We verwachten nu dat de items DICTS zijn (van upload_file_to_storage), maar zijn flexibel.
            if isinstance(b, dict) and b.get("url"):
                urls.append(str(b["url"]))
            elif isinstance(b, str):
                urls.append(b)
        return "\n".join(urls) if urls else None
    except Exception:
        return None

def normalize_klacht_row(row):
    """Return a copy of the klacht row with new schema fields mapped to legacy keys for templates."""
    if not row:
        return {}
    k = dict(row)
    # id fields
    verantwoordelijke_id = k.get('verantwoordelijke_id') or k.get('vertegenwoordiger_id')
    k['verantwoordelijke_id'] = verantwoordelijke_id
    k['vertegenwoordiger_id'] = verantwoordelijke_id
    # naam fallback
    if k.get('verantwoordelijke') and not k.get('vertegenwoordiger'):
        k['vertegenwoordiger'] = k.get('verantwoordelijke')
    # text mappings
    if 'klacht_omschrijving' in k and 'reden_afwijzing' not in k:
        k['reden_afwijzing'] = k.get('klacht_omschrijving')
    if 'reden_afwijzing' in k and 'klacht_omschrijving' not in k:
        k['klacht_omschrijving'] = k.get('reden_afwijzing')
    if 'opmerking_status_wijziging' in k and 'gm_opmerking' not in k:
        k['gm_opmerking'] = k.get('opmerking_status_wijziging')
    if 'gm_opmerking' in k and 'opmerking' not in k:
        k['opmerking'] = k.get('gm_opmerking')
    if 'opmerking_status_wijziging' in k and 'opmerking' not in k:
        k['opmerking'] = k.get('opmerking_status_wijziging')
    # businessunit id + naam
    bu_id = k.get('businessunit_id')
    k['businessunit_id'] = bu_id
    bu_name = None
    try:
        if isinstance(k.get('businessunit_ref'), dict):
            k['businessunit'] = k.get('businessunit') or k['businessunit_ref'].get('naam')
        if isinstance(k.get('businessunit'), dict):
            bu_name = k['businessunit'].get('naam')
        elif k.get('businessunit'):
            bu_name = k.get('businessunit')
        else:
            bu_name = get_businessunit_name(bu_id)
    except Exception:
        bu_name = None
    k['businessunit'] = bu_name
    return k
@main.route('/user/klachten')
def user_klachten():
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))

    role = normalized_role()
    sort_order = request.args.get('sort_order', 'nieuwste')
    try:
        # helper om missende kolom uit Supabase foutboodschap te halen
        def parse_missing_column(errmsg):
            if not errmsg:
                return None
            m = re.search(r"'([^']+)' column", str(errmsg))
            return m.group(1) if m else None

        klachten_raw = []
        # Try to select with relational joins so fewer server calls are required (incl. verantwoordelijke en businessunit naam)
        try:
            sort_ascending = True if sort_order == 'oudste' else False  # standaard: nieuwste eerst (desc)

            query = supabase.table("klacht").select("*, klant:klant_id(klantnaam), categorie:probleemcategorie(type), verantwoordelijke:verantwoordelijke_id(naam), businessunit_ref:businessunit_id(naam)").order("datum_melding", {"ascending": sort_ascending})
            # if User: only their own klachten
            if role == 'User':
                user_id_int = safe_int(session['user_id'])
                query = query.eq("verantwoordelijke_id", user_id_int)
            elif role == 'Key user':
                bu_id = session.get('businessunit_id')
                if bu_id:
                    query = query.eq("businessunit_id", safe_int(bu_id))
            response = query.execute()
            check_supabase_response(response, "fetching klachten")
            klachten_raw = response.data if response.data else []
        except Exception as e:
            # Fallback: simpler select; if something went wrong with joins we still get data
            print(f"Warning: join select failed, falling back. Reason: {e}")
            # detect missende kolom
            missing_col = parse_missing_column(e)
            query = supabase.table("klacht").select("*")
            if role == 'User':
                user_id_int = safe_int(session['user_id'])
                query = query.eq("verantwoordelijke_id", user_id_int)
            elif role == 'Key user':
                bu_id = session.get('businessunit_id')
                if bu_id:
                    query = query.eq("businessunit_id", safe_int(bu_id))
            try:
                response = query.execute()
                check_supabase_response(response, "fetching klachten fallback")
                klachten_raw = response.data if response.data else []
            except Exception as e2:
                print(f"Warning: fallback select failed: {e2}")
                klachten_raw = []

        # Hier passen we normalize_klacht_row toe zonder bijlages te normaliseren,
        # dit doen we later voor elke klacht om de loop te vermijden.
        klachten = [normalize_klacht_row(k) for k in klachten_raw]

        # Attach verantwoordelijke naam to each complaint (for filtering and display)
        rep_map = {}
        reps_for_filter = []
        try:
            rep_ids = [safe_int(k.get('verantwoordelijke_id')) for k in klachten if safe_int(k.get('verantwoordelijke_id'))]
            rep_ids = [r for r in rep_ids if isinstance(r, int)]
            if rep_ids:
                rep_resp = supabase.table("gebruiker").select("gebruiker_id, naam").in_("gebruiker_id", rep_ids).execute()
                check_supabase_response(rep_resp, "fetch verantwoordelijken for klachten")
                rep_map = {safe_int(r.get('gebruiker_id')): r.get('naam') for r in (rep_resp.data or []) if r.get('gebruiker_id') is not None}
            for k in klachten:
                rep_id = safe_int(k.get('verantwoordelijke_id'))
                rep_name = ''
                if isinstance(k.get('verantwoordelijke'), dict):
                    rep_name = k['verantwoordelijke'].get('naam') or ''
                if not rep_name and isinstance(k.get('vertegenwoordiger'), dict):
                    rep_name = k['vertegenwoordiger'].get('naam') or ''
                if not rep_name:
                    rep_name = rep_map.get(rep_id)
                if not rep_name and rep_id is not None:
                    try:
                        single_resp = supabase.table("gebruiker").select("naam").eq("gebruiker_id", rep_id).execute()
                        check_supabase_response(single_resp, "fetch verantwoordelijke naam single")
                        if single_resp.data and single_resp.data[0].get('naam'):
                            rep_name = single_resp.data[0].get('naam')
                            rep_map[rep_id] = rep_name
                    except Exception as ex_fetch_rep:
                        print(f"Warning: kon verantwoordelijke naam niet ophalen voor id {rep_id}: {ex_fetch_rep}")
                if rep_name:
                    k['verantwoordelijke_naam'] = rep_name
                    k['vertegenwoordiger_naam'] = rep_name
                    if not k.get('verantwoordelijke'):
                        k['verantwoordelijke'] = {'naam': rep_name}
                    if not k.get('vertegenwoordiger'):
                        k['vertegenwoordiger'] = {'naam': rep_name}
            reps_for_filter = [{'id': rid, 'naam': nm} for rid, nm in rep_map.items() if nm]
            reps_for_filter = sorted(reps_for_filter, key=lambda x: x['naam'].lower())
        except Exception as e:
            print(f"Warning: verantwoordelijke info kon niet geladen worden: {e}")
            reps_for_filter = []
        # Apply filters from GET params
        klant_id = request.args.get('klant_id')
        klant_naam = request.args.get('klant_naam')
        if not klant_id and klant_naam:
            try:
                krespf = supabase.table("klant").select("klant_id").ilike("klantnaam", klant_naam).execute()
                if krespf.data and len(krespf.data) > 0:
                    klant_id = krespf.data[0].get('klant_id')
            except Exception as e:
                print(f"Klant lookup via naam mislukt: {e}")
        categorie_id = request.args.get('categorie_id')
        status = request.args.get('status')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        businessunit_filter = (request.args.get('businessunit') or '').strip()
        verantwoordelijke_naam = (request.args.get('verantwoordelijke_naam') or request.args.get('vertegenwoordiger_naam') or '').strip()
        high_priority = (request.args.get('high_priority') or '').lower() in ('true', '1', 'on')
        filters_applied = any([
            klant_id, klant_naam, categorie_id, status, date_from, date_to, businessunit_filter, verantwoordelijke_naam, high_priority
        ])

        if klant_id:
            klachten = [k for k in klachten if str(k.get('klant_id')) == str(klant_id)]
        if categorie_id:
            klachten = [k for k in klachten if str(k.get('categorie_id')) == str(categorie_id)]
        if status:
            klachten = [k for k in klachten if k.get('status') == status]
        if verantwoordelijke_naam and role in ('Admin', 'Key user'):
            name_lower = verantwoordelijke_naam.lower()
            def match_rep(k):
                nm = ''
                if isinstance(k.get('verantwoordelijke'), dict):
                    nm = k['verantwoordelijke'].get('naam') or ''
                if not nm and k.get('verantwoordelijke_id') in rep_map:
                    nm = rep_map.get(k.get('verantwoordelijke_id')) or ''
                return name_lower in nm.lower()
            klachten = [k for k in klachten if match_rep(k)]
        if date_from:
            klachten = [k for k in klachten if k.get('datum_melding') and str(k['datum_melding'])[:10] >= date_from]
        if date_to:
            klachten = [k for k in klachten if k.get('datum_melding') and str(k['datum_melding'])[:10] <= date_to]
        # normalize businessunit field
        bu_session = (session.get('businessunit_naam') or '').strip()
        for k in klachten:
            if not k.get('businessunit'):
                k['businessunit'] = get_bu_value(k) or bu_session

        # apply role-based businessunit filter locally for key user
        if role == 'Key user' and bu_session:
            klachten = [k for k in klachten if (k.get('businessunit') == bu_session)]

        if businessunit_filter and role != 'Key user':
            klachten = [k for k in klachten if get_bu_value(k) == businessunit_filter.strip()]

        # Prioriteitsfilter wordt pas na de andere filters toegepast
        if high_priority:
            klachten = [k for k in klachten if k.get('prioriteit')]

        # Sorteer na het toepassen van filters op klacht_id (proxy voor exacte volgorde, omdat datum_melding geen tijd bevat).
        klachten = sorted(
            klachten,
            key=lambda k: safe_int(k.get('klacht_id')) or 0,
            reverse=(sort_order != 'oudste')
        )

        # Geen fallback naar alle klachten; leeg resultaat betekent geen matches voor de huidige filters.

        # categorieen for filter options (ORM + fallback)
        categorieen = get_categorieen_list()

        klanten_resp = supabase.table("klant").select("klant_id, klantnaam").execute()
        check_supabase_response(klanten_resp, "fetching klanten")
        klanten = klanten_resp.data if klanten_resp.data else []
        klanten_map = {k['klant_id']: k.get('klantnaam') for k in klanten if k.get('klant_id') is not None}

        # dynamic businessunits from table
        businessunits_used = get_businessunits_list()
        status_options = get_status_options()
        # ensure klantnaam aanwezig
        for k in klachten:
            if not k.get('klant') and k.get('klant_id') in klanten_map:
                k['klant'] = {'klantnaam': klanten_map.get(k.get('klant_id'))}

        return render_template('user_klachten.html',
                               klachten=klachten,
                               categorieen=categorieen,
                               klanten=klanten,
                               businessunits=businessunits_used,
                               status_options=status_options,
                               vertegenwoordigers=reps_for_filter,
                               filters_applied=filters_applied,
                               sort_order=sort_order,
                               high_priority=high_priority)
    except Exception as e:
        print(f"Exception in user_klachten: {e}")
        traceback.print_exc()
        flash('Er ging iets mis bij het ophalen van klachten', 'error')
        # Return with empty lists so template can still render
        return render_template(
            'user_klachten.html',
            klachten=[],
            categorieen=[],
            klanten=[],
            businessunits=get_businessunits_list(),
            status_options=get_status_options(),
            vertegenwoordigers=[],
            filters_applied=False,
            sort_order=request.args.get('sort_order', 'nieuwste'),
            high_priority=False
        )


@main.route('/user/klacht/<int:klacht_id>/details')
def klacht_details(klacht_id):
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))

    try:
        # use relational select to get klant + categorie with one call (incl. ondernemingsnummer)
        klacht_response = supabase.table("klacht").select(
            "*, klant:klant_id(klantnaam, ondernemingsnummer), categorie:probleemcategorie(type), verantwoordelijke:verantwoordelijke_id(naam), businessunit_ref:businessunit_id(naam)"
        ).eq("klacht_id", safe_int(klacht_id)).execute()
        check_supabase_response(klacht_response, "fetching single complaint")
        if not klacht_response.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        klacht_data = normalize_klacht_row(klacht_response.data[0])

        # Authorization check - ensure numbers are comparable
        if not can_view_klacht(klacht_data, safe_int(session['user_id']), session.get('user_rol')):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        try:
            klant_id_val = safe_int(klacht_data.get('klant_id'))
            if klant_id_val:
                klant_obj = db.session.get(Klant, int(klant_id_val))
                if klant_obj is None:
                    klant_obj = db.session.query(Klant).get(int(klant_id_val))
                if klant_obj:
                    # Voeg ondernemingsnummer toe wanneer Supabase-relatie het niet meegeeft
                    klacht_data['klant'] = klant_obj
                    klacht_data['ondernemingsnummer'] = klant_obj.ondernemingsnummer
        except Exception as e:
            print(f"Warning: kon klant {klacht_data.get('klant_id')} niet laden via ORM: {e}")

        # statushistoriek (defensive)
        try:
            sh_resp = supabase.table("statushistoriek").select("*").eq("klacht_id", safe_int(klacht_id)).order("datum_wijziging", desc=True).execute()
            check_supabase_response(sh_resp, "status historiek")
            statushistoriek = sh_resp.data if sh_resp.data else []
        except Exception as e:
            print(f"Warning: failed to fetch status historiek for {klacht_id}: {e}")
            statushistoriek = []

        # categorieen (for edit dropdown)
        categorieen = get_categorieen_list()

        # vertegenw if manager/key user
        vertegenw = []
        current_role = normalized_role()
        if current_role in ('Admin', 'Key user'):
            try:
                # Laat alle gebruikers (ongeacht rol) zien zodat je aan iedereen kunt toewijzen
                rep_query = supabase.table("gebruiker").select("gebruiker_id, naam, rol, businessunit_id")
                reps_resp = rep_query.execute()
                check_supabase_response(reps_resp, "fetching reps")
                vertegenw_raw = reps_resp.data if reps_resp.data else []
                vertegenw = sorted(vertegenw_raw, key=lambda u: (u.get('naam') or '').lower())
            except Exception as e:
                print(f"Warning: could not fetch vertegenw: {e}")
                vertegenw = []
        # BELANGRIJK: Bijlages omzetten van URL-string naar template-dict structuur
        # Deze is al genormaliseerd in normalize_klacht_row, maar we roepen het hier opnieuw aan om zeker te zijn van de dicts
        klacht_data['bijlages'] = normalize_bijlages(klacht_data.get('bijlages')) 

        # After we fetched klacht_data in klacht_details, ensure we have the creator name even if relation wasn't joined:
        if not klacht_data.get('verantwoordelijke') and klacht_data.get('verantwoordelijke_id'):
            try:
                uresp = supabase.table("gebruiker").select("naam").eq("gebruiker_id", int(klacht_data['verantwoordelijke_id'])).execute()
                check_supabase_response(uresp, "fetch creator name for details")
                if uresp.data and len(uresp.data) > 0:
                    klacht_data['verantwoordelijke'] = {'naam': uresp.data[0].get('naam')}
            except Exception as e:
                print(f"Warning: could not fetch creator name for klacht {klacht_id}: {e}")

        return render_template(
            'klacht_details.html',
            klacht=klacht_data,
            klacht_id=klacht_id,
            categorieen=categorieen,
            statushistoriek=statushistoriek,
            vertegenw=vertegenw,
            businessunits=get_businessunits_list(),
            status_options=get_status_options()
        )
    except Exception as e:
        print(f"Exception in klacht_details: {e}")
        traceback.print_exc()
        flash('Er ging iets mis bij het ophalen van de klacht details', 'error')
        return redirect(url_for('main.user_klachten'))


# Helper: upload one file to Supabase Storage and return bijlage dict (met URL)
def upload_file_to_storage(file_obj, store_in_db=False, klacht_id=None, klant_naam=None, klant_id_val=None, businessunit_name=None):
    if not file_obj or not getattr(file_obj, 'filename', None):
        return None
    try:
        safe_name = secure_filename(file_obj.filename)
        unique_id = str(uuid.uuid4())
        
        # NIEUW: Betere bestandsnaam en pad
        
        # 1. Bepaal Business Unit Deel
        # We maken de naam veilig voor een map en vervangen spaties door underscores
        bu_part = secure_filename(businessunit_name.replace(' ', '_')) if businessunit_name else "OnbekendeBU"
        
        # 2. Bepaal Klant Deel
        # Gebruik alleen de veilige, verkorte naam van de klant (max 10 karakters)
        if klant_naam:
            # Maak veilig en beperk tot 10 karakters (of hele naam als korter)
            klant_part = secure_filename(klant_naam).replace(' ', '_')[:15]
        else:
            klant_part = "OnbekendeKlant"
            
        # 3. Bepaal Klacht Deel
        klacht_part = f"Klacht_{klacht_id}" if klacht_id else "TEMP"
        
        # NIEUWE Pad: {BUCKET_NAME}/<Businessunit_Naam>/<KlantNaam>/Klacht_<ID>/<UUID>_<OriginalName>
        # Let op: BUCKET_NAME is al de root map (e.g. "bijlages")
        path_in_bucket = f"{bu_part}/{klant_part}/{klacht_part}/{unique_id}_{safe_name}"
        
        content_type = getattr(file_obj, 'mimetype', 'application/octet-stream')
        # Ensure pointer at start
        try:
            file_obj.stream.seek(0)
        except Exception:
            pass
        
        # File object kan nu uit BytesIO komen (in klacht_aanmaken)
        if hasattr(file_obj, 'read'):
            file_bytes = file_obj.read()
        else:
            file_bytes = file_obj['bytes'] # Fallback/assuming dict if needed

        # Dwing het gebruik van Supabase Storage af (STORE_FILES_IN_DB is False)
        if not STORE_FILES_IN_DB:
            # Upload to Supabase Storage
            upload_response = supabase.storage.from_(BUCKET_NAME).upload(path_in_bucket, file_bytes)
            file_url = f"{supabase_url}/storage/v1/object/public/{BUCKET_NAME}/{path_in_bucket}"
            bijlage = {
                "id": unique_id,
                "url": file_url,
                "naam": safe_name,
                "content_type": content_type,
                "upload_date": datetime.utcnow().isoformat()
            }
            return bijlage
        else:
             # Oude Base64/DB opslag - Hoort niet meer te lopen
            b64 = base64.b64encode(file_bytes).decode('utf-8')
            data_url = f"data:{content_type};base64,{b64}"
            return {
                "id": unique_id,
                "naam": safe_name,
                "content_type": content_type,
                "content": b64,
                "url": data_url,
                "upload_date": datetime.utcnow().isoformat()
            }
    except Exception as e:
        print(f"Upload error: {e}")
        traceback.print_exc()
        return None
    
# Helper: derive path in bucket from public URL and delete the object (no-op for data: urls)
def delete_file_from_storage(file_url):
    try:
        if not file_url:
            return None
        # If this is a data-url (content in DB), skip deletion from Storage
        if file_url.startswith('data:'):
            # nothing to delete from Storage
            return None
        # Expect URL like: {supabase_url}/storage/v1/object/public/{BUCKET_NAME}/{path_in_bucket}
        token = f"/{BUCKET_NAME}/"
        if token in file_url:
            path_in_bucket = file_url.split(token, 1)[1]
            delete_resp = supabase.storage.from_(BUCKET_NAME).remove([path_in_bucket])
            return delete_resp
        else:
            print(f"Could not parse path from URL: {file_url}")
            return None
    except Exception as e:
        print(f"Delete storage error: {e}")
        traceback.print_exc()
        return None


@main.route('/user/klacht/aanmaken', methods=['GET', 'POST'])
def klacht_aanmaken():
    # Allow Users, Key users and Admins to create complaints
    if 'user_id' not in session or normalized_role() not in ('User', 'Key user', 'Admin'):
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    
    # Haal klanten en categorieën op voor dropdowns
    try:
        klanten_response = supabase.table("klant").select("klant_id, klantnaam").execute()
        klanten = klanten_response.data if klanten_response.data else []
        categorieen = get_categorieen_list()
        
    except Exception as e:
        print(f"Error bij ophalen data: {e}")
        klanten = []
        categorieen = []

    bu_prefill = safe_int(session.get('businessunit_id'))
    
    # Haal initiële suggesties op voor de GET-pagina of als fallback na fout
    suggested_categorie_type = suggest_categorie_safe(
        request.form.get('reden_afwijzing', '').strip(),
        request.form.get('mogelijke_oorzaak', '').strip(),
        businessunit_id=bu_prefill if isinstance(bu_prefill, int) else None
    )
    suggested_categorie_id = find_categorie_id_by_type(categorieen, suggested_categorie_type)
    selected_categorie_id = request.form.get('categorie_id', '').strip() or suggested_categorie_id
    
    if request.method == 'POST':
        try:
            # Haal form data op
            klant_id = request.form.get('klant_id', '').strip()
            klant_naam = request.form.get('klant_naam', '').strip()
            categorie_id = request.form.get('categorie_id', '').strip()
            order_nummer = request.form.get('order_nummer', '').strip()
            artikelnummer = request.form.get('artikelnummer', '').strip()
            artikelnaam = request.form.get('artikel_naam', '').strip()
            aantal_eenheden = request.form.get('aantal_eenheden', '').strip()
            mogelijke_oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
            klacht_omschrijving = request.form.get('reden_afwijzing', '').strip()
            
            # De businessunit naam is cruciaal voor het pad, zorg dat deze correct is
            businessunit = request.form.get('businessunit', '').strip() or (session.get('businessunit_naam') or '').strip()
            bu_id = resolve_or_create_businessunit(businessunit) if businessunit else None
            
            # 1. Bepaal/Creëer Klant ID en Klantnaam
            klant_naam_used = klant_naam
            if not klant_id and klant_naam:
                # Probeer klant_id op te lossen/creëren
                try:
                    kresp = supabase.table("klant").select("klant_id").ilike("klantnaam", klant_naam).execute()
                    if kresp.data and len(kresp.data) > 0:
                        klant_id = kresp.data[0].get('klant_id')
                except Exception as ie:
                    print(f"Klant zoeken op naam mislukt: {ie}")
                if not klant_id:
                    try:
                        insert_resp = supabase.table("klant").insert({"klantnaam": klant_naam}).execute()
                        check_supabase_response(insert_resp, "insert new klant by name")
                        if insert_resp.data and len(insert_resp.data) > 0:
                            klant_id = insert_resp.data[0].get('klant_id')
                    except Exception as ie2:
                        print(f"Nieuwe klant aanmaken mislukt: {ie2}")
            elif klant_id and not klant_naam:
                # Haal de naam op als we alleen het ID hebben
                try:
                    kresp = supabase.table("klant").select("klantnaam").eq("klant_id", int(klant_id)).execute()
                    if kresp.data and len(kresp.data) > 0:
                        klant_naam_used = kresp.data[0].get('klantnaam')
                except Exception:
                    pass
            
            # Valideer verplichte velden
            if not klant_id or not categorie_id or not order_nummer or not artikelnummer or not aantal_eenheden or not klacht_omschrijving or not businessunit:
                flash('Klant, categorie, ordernummer, artikelnummer, aantal eenheden, businessunit en klacht omschrijving zijn verplicht', 'error')
                # Zorg ervoor dat de suggestie correct werkt, ook na een POST-fout
                suggested_categorie_type = suggest_categorie_safe(
                    klacht_omschrijving,
                    mogelijke_oorzaak,
                    businessunit_id=safe_int(bu_id) if bu_id is not None else None
                )
                suggested_categorie_id = find_categorie_id_by_type(categorieen, suggested_categorie_type)
                selected_categorie_id = categorie_id or suggested_categorie_id
                return render_template(
                    'klacht_aanmaken.html',
                    user_naam=session.get('user_naam'),
                    klanten=klanten,
                    categorieen=categorieen,
                    businessunits=get_businessunits_list(),
                    suggested_categorie_id=suggested_categorie_id,
                    suggested_categorie_type=suggested_categorie_type,
                    selected_categorie_id=selected_categorie_id
                )

            # 2. Bepaal categorie op basis van suggestie (indien nodig)
            suggested_categorie_type = suggest_categorie_safe(
                klacht_omschrijving,
                mogelijke_oorzaak,
                businessunit_id=safe_int(bu_id) if bu_id is not None else None
            )
            suggested_categorie_id = find_categorie_id_by_type(categorieen, suggested_categorie_type)
            if not categorie_id and suggested_categorie_id:
                categorie_id = str(suggested_categorie_id)
            selected_categorie_id = categorie_id or suggested_categorie_id

            # 3. Bestanden in geheugen opslaan (upload uitstellen)
            uploaded_files_in_memory = []
            files = []
            files += request.files.getlist('bijlage') or []
            files += request.files.getlist('bijlage[]') or []
            
            seen_key = set()
            for f in files:
                if not f or not getattr(f, 'filename', None):
                    continue
                # Simple check for empty file and deduplication
                f.stream.seek(0, os.SEEK_END)
                size = f.stream.tell()
                f.stream.seek(0)
                if size == 0:
                    continue
                key = (f.filename, size)
                if key in seen_key:
                    continue
                seen_key.add(key)
                
                # Lees de bytes en sla ze in het geheugen op, samen met de metadata
                file_bytes = f.read()
                f.stream.seek(0) # Reset pointer
                uploaded_files_in_memory.append({
                    "filename": f.filename,
                    "mimetype": getattr(f, 'mimetype', 'application/octet-stream'),
                    "bytes": file_bytes # Opslaan in geheugen
                })

            # Alleen datum (zonder uur)
            vandaag = date.today().isoformat()

            # 4. Klacht aanmaken (EERST ZONDER BIJLAGES)
            artikelnummer = ensure_product_exists(artikelnummer, artikelnaam)
            order_nummer = ensure_order_exists(order_nummer, klant_id)
            nieuwe_klacht = {
                'verantwoordelijke_id': session['user_id'],
                'klant_id': int(klant_id),
                'categorie_id': int(categorie_id),
                'order_nummer': order_nummer,
                'artikelnummer': safe_int(artikelnummer) if artikelnummer else None,
                'aantal_eenheden': safe_int(aantal_eenheden) if aantal_eenheden else None,
                'mogelijke_oorzaak': mogelijke_oorzaak or None,
                'bijlages': None,              # <--- Eerst op None, upload komt later
                'prioriteit': False,
                'status': 'Ingediend',
                'datum_melding': vandaag,
                'klacht_omschrijving': klacht_omschrijving,
                'businessunit_id': bu_id,
                'opmerking_status_wijziging': None,
                'datum_laatst_bewerkt': vandaag
            }
            
            def parse_missing_column(errmsg):
                if not errmsg:
                    return None
                m = re.search(r"'([^']+)' column", errmsg)
                if m:
                    return m.group(1)
                return None

            def without_column(payload, colname):
                return {k: v for k, v in payload.items() if k != colname}

            def safe_insert(payload):
                try:
                    resp = supabase.table("klacht").insert(payload).execute()
                    err = getattr(resp, 'error', None)
                    if err:
                        raise Exception(getattr(err, 'message', str(err)))
                    return resp
                except Exception as ex:
                    msg = str(ex)
                    col = parse_missing_column(msg)
                    if col:
                        cleaned = without_column(payload, col)
                        resp_clean = supabase.table("klacht").insert(cleaned).execute()
                        clean_err = getattr(resp_clean, 'error', None)
                        if clean_err:
                            raise Exception(getattr(clean_err, 'message', str(clean_err)))
                        return resp_clean
                    raise

            response = safe_insert(nieuwe_klacht)

            if response.data:
                nieuw_id = response.data[0].get('klacht_id')
                
                # 5. Bestanden uploaden met de nieuwe Klacht ID en de klantinformatie
                bijlages_uploaded = []
                
                for file_data in uploaded_files_in_memory:
                    try:
                        # Creëer een bestand-object-achtige structuur van de in-memory bytes
                        file_obj_temp = io.BytesIO(file_data['bytes'])
                        # Voeg filename en mimetype toe zodat upload_file_to_storage werkt
                        file_obj_temp.filename = file_data['filename']
                        file_obj_temp.mimetype = file_data['mimetype']
                        
                        # upload_file_to_storage met de NIEUWE parameters
                        uploaded = upload_file_to_storage(
                            file_obj_temp, 
                            store_in_db=STORE_FILES_IN_DB,
                            klacht_id=nieuw_id,
                            klant_naam=klant_naam_used,
                            klant_id_val=klant_id,
                            businessunit_name=businessunit # <--- NIEUWE PARAMETER
                        )
                        if uploaded:
                            bijlages_uploaded.append(uploaded)
                    except Exception as e:
                        print(f"DEBUG - Error uploading file {file_data['filename']} after insert: {e}")
                
                # 6. Update de klachtrij met de bijlage-URL's
                if bijlages_uploaded:
                    serialized_bijlages = serialize_bijlages_for_db(bijlages_uploaded)
                    update_resp = supabase.table("klacht").update({'bijlages': serialized_bijlages}).eq("klacht_id", nieuw_id).execute()
                    check_supabase_response(update_resp, "update klacht met bijlages na upload")
                
                
                flash('Klacht succesvol aangemaakt!', 'success')
                return redirect(url_for('main.user_klachten'))
            else:
                error_msg = 'Er ging iets mis bij het aanmaken van de klacht'
                if hasattr(response, 'error') and response.error:
                    error_msg += f": {response.error.message}"
                flash(error_msg, 'error')
                
        except Exception as e:
            error_msg = f'Er ging iets mis bij het aanmaken van de klacht: {str(e)}'
            flash(error_msg, 'error')
            print(f"ERROR - Exception: {str(e)}")
    
    return render_template(
        'klacht_aanmaken.html',
        user_naam=session.get('user_naam'),
        klanten=klanten,
        categorieen=categorieen,
        businessunits=get_businessunits_list(),
        suggested_categorie_id=suggested_categorie_id,
        suggested_categorie_type=suggested_categorie_type,
        selected_categorie_id=selected_categorie_id
    )


@main.route('/user/klacht/suggest-categorie', methods=['POST'])
def suggest_categorie():
    if 'user_id' not in session or normalized_role() not in ('User', 'Key user', 'Admin'):
        return {"error": "Unauthorized"}, 401
    klacht_omschrijving = (request.form.get('klacht_omschrijving') or '').strip()
    mogelijke_oorzaak = (request.form.get('mogelijke_oorzaak') or '').strip()
    businessunit_context = (
        request.form.get('businessunit_id')
        or request.form.get('businessunit')
        or session.get('businessunit_id')
    )
    suggested_type = suggest_categorie_safe(
        klacht_omschrijving,
        mogelijke_oorzaak,
        businessunit_id=safe_int(businessunit_context) if businessunit_context is not None else None
    )
    return suggested_type or "Andere", 200, {"Content-Type": "text/plain"}


@main.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    if normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.user_dashboard'))
    businessunits_used = get_businessunits_list()

    total_klachten = 0
    today_new = 0
    total_gebruikers = 0
    today_str = date.today().isoformat()
    try:
        # tel gebruikers
        try:
            users_resp = supabase.table("gebruiker").select("gebruiker_id").execute()
            check_supabase_response(users_resp, "count gebruikers admin")
            total_gebruikers = len(users_resp.data or [])
        except Exception as ue:
            print(f"Warning: count gebruikers failed: {ue}")
            total_gebruikers = 0

        # tel klachten (open) en vandaag
        try:
            klachten_resp = supabase.table("klacht").select("*").execute()
            check_supabase_response(klachten_resp, "count klachten admin")
            klachten_all = klachten_resp.data if klachten_resp.data else []
            def is_open(k):
                return (k.get('status') or '').strip() != 'Afgehandeld'
            total_klachten = len([k for k in klachten_all if is_open(k)])
            today_new = len([k for k in klachten_all if is_klacht_today(k, today_str)])
        except Exception as ke:
            print(f"Warning: count klachten failed: {ke}")
            total_klachten = 0
            today_new = 0
    except Exception as e:
        print(f"Error admin stats: {e}")
        traceback.print_exc()
        total_klachten = 0
        total_gebruikers = 0
        today_new = 0

    return render_template('admin_dashboard.html',
                           total_klachten=total_klachten,
                           total_gebruikers=total_gebruikers,
                           today_new=today_new,
                           businessunit=session.get('businessunit_naam') or '',
                           today_str=today_str,
                           businessunits=businessunits_used)

@main.route('/admin/users/manage')
def admin_users_page():
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        users_resp = supabase.table("gebruiker").select("gebruiker_id, naam, email, rol, businessunit_id").execute()
        check_supabase_response(users_resp, "fetch users for beheer")
        gebruikers = users_resp.data if users_resp.data else []
        for u in gebruikers:
            pid = safe_int(u.get('businessunit_id'))
            bu_name = get_businessunit_name(pid)
            u['businessunit_naam'] = bu_name
    except Exception as e:
        print(f"Error fetching users: {e}")
        gebruikers = []
    businessunits_used = get_businessunits_list()
    return render_template('admin_users.html', gebruikers=gebruikers, businessunits=businessunits_used)

# Update role usage when creating users
@main.route('/admin/users', methods=['POST'])
def admin_create_user():
    if 'user_id' not in session or not is_manager_role():
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.user_dashboard'))
    # form fields
    naam = request.form.get('naam')
    email = request.form.get('email')
    rol = request.form.get('rol') or 'User'
    wachtwoord = request.form.get('wachtwoord') or 'changeme'
    businessunit_raw = request.form.get('businessunit') or None

    if not naam or not email:
        flash('Naam en email zijn verplicht', 'error')
        return redirect(url_for('main.user_dashboard'))
    try:
        hashed = generate_password_hash(wachtwoord)
        bu_id = resolve_or_create_businessunit(businessunit_raw)
        user_obj = {
            'naam': naam,
            'email': email,
            'rol': (rol or '').strip().capitalize(),
            'wachtwoord': hashed,
            'businessunit_id': bu_id
        }
        resp = supabase.table("gebruiker").insert(user_obj).execute()
        check_supabase_response(resp, "admin create user")
        if getattr(resp, "error", None):
            msg = resp.error.message if hasattr(resp.error, "message") else str(resp.error)
            flash(f'Fout bij aanmaken gebruiker: {msg}', 'error')
        elif resp.data:
            flash('Gebruiker succesvol aangemaakt', 'success')
        else:
            flash('Fout bij aanmaken gebruiker (onbekend)', 'error')
    except Exception as e:
        print(f"Error creating user: {e}")
        flash('Er ging iets mis bij het aanmaken van de gebruiker', 'error')
    # Redirect to users beheer page
    return redirect(url_for('main.admin_users_page'))

@main.route('/admin/users/<int:user_id>/update', methods=['POST'])
def admin_update_user(user_id):
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    rol = request.form.get('rol')
    businessunit_raw = request.form.get('businessunit')
    try:
        update_obj = {}
        if rol:
            update_obj['rol'] = rol.strip().capitalize()
        if businessunit_raw is not None:
            # "" betekent expliciet leegmaken
            if str(businessunit_raw).strip() == '':
                update_obj['businessunit_id'] = None
            else:
                update_obj['businessunit_id'] = resolve_or_create_businessunit(businessunit_raw)
        if update_obj:
            resp = supabase.table("gebruiker").update(update_obj).eq("gebruiker_id", user_id).execute()
            check_supabase_response(resp, "admin update user")
            if getattr(resp, "error", None):
                msg = resp.error.message if hasattr(resp.error, "message") else str(resp.error)
                flash(f'Fout bij bijwerken gebruiker: {msg}', 'error')
            else:
                flash('Gebruiker bijgewerkt', 'success')
    except Exception as e:
        print(f"admin_update_user error: {e}")
        flash('Fout bij bijwerken gebruiker', 'error')
    return redirect(url_for('main.admin_users_page'))

@main.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        # Block deletion when the user still owns open complaints
        klachten_resp = supabase.table("klacht").select("klacht_id, status").eq("verantwoordelijke_id", user_id).execute()
        check_supabase_response(klachten_resp, "admin delete user fetch klachten")
        klachten = klachten_resp.data or []
        open_klachten = [k for k in klachten if (k.get('status') or '').strip() not in ('Afgehandeld', 'Afgewezen')]
        if open_klachten:
            count_open = len(open_klachten)
            flash(f'Kan gebruiker niet verwijderen: er zijn nog {count_open} openstaande klacht(en). Wijs ze eerst toe aan een andere verantwoordelijke.', 'error')
            return redirect(url_for('main.admin_users_page'))

        resp = supabase.table("gebruiker").delete().eq("gebruiker_id", user_id).execute()
        check_supabase_response(resp, "admin delete user")
        # Verify that the row is actually gone
        verify_resp = supabase.table("gebruiker").select("gebruiker_id").eq("gebruiker_id", user_id).execute()
        check_supabase_response(verify_resp, "admin delete user verify")
        if verify_resp.data:
            flash('Fout bij verwijderen gebruiker', 'error')
        else:
            flash('Gebruiker verwijderd', 'success')
    except Exception as e:
        print(f"admin_delete_user error: {e}")
        flash('Fout bij verwijderen gebruiker', 'error')
    return redirect(url_for('main.admin_users_page'))

@main.route('/admin/businessunits', methods=['GET'])
def admin_businessunits_page():
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        resp = supabase.table("businessunit").select("businessunit_id, naam").order("naam").execute()
        check_supabase_response(resp, "fetch businessunits admin page")
        businessunits = resp.data if resp.data else []
    except Exception as e:
        print(f"admin_businessunits_page error: {e}")
        businessunits = []
        flash('Kon businessunits niet ophalen', 'error')
    return render_template('admin_businessunits.html', businessunits=businessunits)

@main.route('/admin/businessunit', methods=['POST'])
def admin_create_businessunit():
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    naam = (request.form.get('naam') or '').strip()
    if not naam:
        flash('Naam van businessunit is verplicht', 'error')
        return redirect(url_for('main.admin_businessunits_page'))
    try:
        # voorkom dubbele insert: check bestaat
        existing = supabase.table("businessunit").select("businessunit_id").eq("naam", naam).execute()
        check_supabase_response(existing, "check bestaande businessunit")
        if existing.data:
            flash('Businessunit bestaat al', 'info')
            return redirect(url_for('main.admin_businessunits_page'))

        # Sommige Supabase-tabellen missen auto-increment op businessunit_id; kies dan handmatig een volgende id
        next_id = 1
        try:
            max_resp = supabase.table("businessunit").select("businessunit_id").order("businessunit_id", desc=True).limit(1).execute()
            check_supabase_response(max_resp, "fetch max businessunit_id")
            if max_resp.data and max_resp.data[0].get('businessunit_id') is not None:
                next_id = int(max_resp.data[0].get('businessunit_id')) + 1
        except Exception as e:
            print(f"Warning: kon max businessunit_id niet bepalen: {e}")

        resp = supabase.table("businessunit").insert({"businessunit_id": next_id, "naam": naam}).execute()
        check_supabase_response(resp, "create businessunit")
        if getattr(resp, "error", None):
            msg = resp.error.message if hasattr(resp.error, "message") else str(resp.error)
            flash(f'Fout bij toevoegen businessunit: {msg}', 'error')
        else:
            flash('Businessunit toegevoegd', 'success')
    except Exception as e:
        print(f"admin_create_businessunit error: {e}")
        flash(f'Fout bij toevoegen businessunit: {e}', 'error')
    return redirect(url_for('main.admin_businessunits_page'))

@main.route('/admin/businessunit/<int:businessunit_id>/delete', methods=['POST'])
def admin_delete_businessunit(businessunit_id):
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        # Voorkom verwijderen als businessunit nog gekoppeld is
        users_check = supabase.table("gebruiker").select("gebruiker_id").eq("businessunit_id", businessunit_id).limit(1).execute()
        check_supabase_response(users_check, "check businessunit in gebruik door gebruikers")
        if users_check.data:
            flash('Kan businessunit niet verwijderen: deze is gekoppeld aan een gebruiker.', 'error')
            return redirect(url_for('main.admin_businessunits_page'))

        klachten_check = supabase.table("klacht").select("klacht_id").eq("businessunit_id", businessunit_id).limit(1).execute()
        check_supabase_response(klachten_check, "check businessunit in gebruik door klachten")
        if klachten_check.data:
            flash('Kan businessunit niet verwijderen: verwijder eerst alle klachten die aan deze businessunit gekoppeld zijn.', 'error')
            return redirect(url_for('main.admin_businessunits_page'))

        del_resp = supabase.table("businessunit").delete().eq("businessunit_id", businessunit_id).execute()
        check_supabase_response(del_resp, "delete businessunit")
        flash('Businessunit verwijderd', 'success')
    except Exception as e:
        print(f"admin_delete_businessunit error: {e}")
        flash('Fout bij verwijderen businessunit', 'error')
    return redirect(url_for('main.admin_businessunits_page'))

@main.route('/keyuser/klacht/<int:klacht_id>/toewijzen', methods=['POST'])
def keyuser_assign_klacht(klacht_id):
    role = normalized_role()
    if 'user_id' not in session or role not in ('Key user','Admin'):
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        # haal klacht op om businessunit te checken
        klacht_resp = supabase.table("klacht").select("businessunit_id").eq("klacht_id", klacht_id).execute()
        check_supabase_response(klacht_resp, "fetch klacht for assign")
        klacht_obj = klacht_resp.data[0] if klacht_resp.data else {}
        if role == 'Key user':
            my_bu = session.get('businessunit_naam')
            complaint_bu = get_businessunit_name(klacht_obj.get('businessunit_id'))
            if my_bu and complaint_bu and complaint_bu != my_bu:
                flash('Toegang geweigerd voor deze businessunit', 'error')
                return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        nieuwe_rep = request.form.get('vertegenwoordiger_id')
        if not nieuwe_rep:
            flash('Geen gebruiker geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Check whether the selected user exists
        new_rep_resp = supabase.table("gebruiker").select("*").eq("gebruiker_id", int(nieuwe_rep)).execute()
        if not new_rep_resp.data:
            flash('Gekozen gebruiker niet gevonden', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # perform the update - Key user can assign across companies
        update_resp = supabase.table("klacht").update({
            'verantwoordelijke_id': int(nieuwe_rep),
            'datum_laatst_bewerkt': datetime.utcnow().isoformat()
        }).eq("klacht_id", klacht_id).execute()

        if update_resp.data:
            flash('Klacht succesvol toegewezen', 'success')
        else:
            flash('Fout bij toewijzen klacht', 'error')

    except Exception as e:
        print(f"Error assigning complaint: {e}")
        traceback.print_exc()
        flash('Er ging iets mis bij toewijzen', 'error')

    return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

@main.route('/manager/klacht/<int:klacht_id>/toewijzen', methods=['POST'])
def manager_assign_klacht(klacht_id):
    # Backwards compatibility alias: call the keyuser assign handler.
    # This simply forwards the request, so any templates using the old endpoint will not break.
    return keyuser_assign_klacht(klacht_id)

@main.route('/keyuser/dashboard')
def keyuser_dashboard():
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    if normalized_role() not in ('Key user', 'Admin'):
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.user_dashboard'))

    total_klachten = 0
    today_new = 0
    today_str = date.today().isoformat()
    try:
        bu_name = session.get('businessunit_naam')
        # helper: parse ontbrekende kolom uit fout
        def parse_missing_column(errmsg):
            if not errmsg:
                return None
            m = re.search(r"'([^']+)' column", str(errmsg))
            return m.group(1) if m else None

        try:
            # haal alles op en tel lokaal (vermijdt kolom-fouten)
            resp_all = supabase.table("klacht").select("*").execute()
            check_supabase_response(resp_all, "fetching keyuser complaints count (all)")
            klachten_all = resp_all.data if resp_all.data else []

            def is_open(k):
                status = (k.get('status') or '').strip()
                # als geen status, beschouw als open
                return status != 'Afgehandeld'

            def bu_matches(k):
                if not bu_name:
                    return True
                val = get_bu_value(k)
                if not val:
                    # als kolom ontbreekt of leeg is, niet wegfilteren
                    return True
                return val == bu_name.strip()

            klachten = [k for k in klachten_all if is_open(k) and bu_matches(k)]

            # fallback: als nog 0, tel alle niet-afgehandelde zonder BU-filter
            if len(klachten) == 0:
                klachten = [k for k in klachten_all if is_open(k)]

            # tel nieuwe klachten van vandaag (status ongeacht, optioneel filter op BU)
            today_new = len([
                k for k in klachten_all
                if is_klacht_today(k, today_str) and (not bu_name or bu_matches(k))
            ])
        except Exception as e:
            print(f"Warning: counting klachten with local filter failed: {e}")
            klachten = []

        total_klachten = len(klachten)

        # Count newly ingediende klachten van vandaag (binnen eigen businessunit)
        # (today_new wordt in bovenstaande blok al berekend; laat fallback leeg)
    except Exception as e:
        print("Error getting keyuser stats:", e)
        traceback.print_exc()
        total_klachten = 0
        klachten = []

    print(f"DEBUG: keyuser_dashboard found {len(klachten)} klachten")
    return render_template('keyuser_dashboard.html', total_klachten=total_klachten, today_new=today_new, today_str=today_str, businessunit=bu_name or '')

# Helper: return normalized role as "User", "Key user", "Admin"
def normalized_role():
    r = (session.get('user_rol') or '').strip()
    if not r:
        return ''
    if r.lower().replace('-', ' ') in ('key user', 'keyuser'):
        return 'Key user'
    if r.lower() == 'admin':
        return 'Admin'
    if r.lower() == 'user':
        return 'User'
    return r.capitalize()

# Use normalized_role in helpers
def is_admin_role():
    return normalized_role() == 'Admin'

def is_manager_role():
    return normalized_role() in ('Admin', 'Key user')

def can_view_klacht(klacht, user_id, user_role):
    role_norm = (user_role or '').strip().capitalize()
    owner_id = klacht.get('verantwoordelijke_id') or klacht.get('vertegenwoordiger_id')
    if role_norm == 'Admin':
        return True
    if role_norm == 'Key user':
        # Key user mag enkel binnen eigen businessunit
        bu = get_bu_value(klacht)
        my_bu = (session.get('businessunit_naam') or '').strip()
        if my_bu and bu and bu != my_bu:
            return False
        return True
    if role_norm == 'User':
        return owner_id == user_id
    return False

def can_edit_klacht(klacht, user_id, user_role):
    role_norm = (user_role or '').strip().capitalize()
    owner_id = klacht.get('verantwoordelijke_id') or klacht.get('vertegenwoordiger_id')
    if role_norm in ('Admin', 'Key user'):
        if role_norm == 'Key user':
            bu = get_bu_value(klacht)
            my_bu = (session.get('businessunit_naam') or '').strip()
            if my_bu and bu and bu != my_bu:
                return False
        return True
    return owner_id == user_id

@main.route('/user/klacht/<int:klacht_id>/bewerken', methods=['POST'])
def klacht_bewerken(klacht_id):
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # Controleer of de klacht van de huidige user is
        klacht_check = supabase.table("klacht").select("verantwoordelijke_id, status").eq("klacht_id", klacht_id).execute()
        
        if not klacht_check.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        klacht_owner_id = klacht_check.data[0].get('verantwoordelijke_id') or klacht_check.data[0].get('vertegenwoordiger_id')
        current_role = session.get('user_rol')
        # authorization: check if current user can edit this complaint
        if not can_edit_klacht({'verantwoordelijke_id': klacht_owner_id}, session['user_id'], current_role):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # Capture old status BEFORE we update anything
        try:
            old_status = klacht_check.data[0].get('status')
        except Exception:
            old_status = None

        # Haal form data op
        order_nummer = request.form.get('order_nummer', '').strip()
        artikelnummer = request.form.get('artikelnummer', '').strip()
        aantal_eenheden = request.form.get('aantal_eenheden', '').strip()
        categorie_id = request.form.get('categorie_id', '').strip()
        mogelijke_oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
        klacht_omschrijving = request.form.get('reden_afwijzing', '').strip()
        businessunit = request.form.get('businessunit', '').strip() or (session.get('businessunit_naam') or '').strip()
        bu_id = resolve_or_create_businessunit(businessunit) if businessunit else None
        verantwoordelijke_id = request.form.get('vertegenwoordiger_id', '').strip()  # nieuw

        # Valideer verplichte velden
        if not categorie_id or not order_nummer or not artikelnummer or not aantal_eenheden or not klacht_omschrijving:
            flash('Categorie, ordernummer, artikelnummer, aantal eenheden en klacht omschrijving zijn verplicht', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Controleer of categorie_id bestaat (ORM met fallback)
        categorie_check = None
        try:
            categorie_check = db.session.query(Probleemcategorie.categorie_id).filter_by(categorie_id=int(categorie_id)).first()
        except Exception as e:
            print(f"Warning: categorie check via ORM faalde: {e}")
            try:
                resp = supabase.table("probleemcategorie").select("categorie_id").eq("categorie_id", int(categorie_id)).execute()
                check_supabase_response(resp, "categorie check fallback supabase")
                if resp.data:
                    categorie_check = True
            except Exception as e2:
                print(f"Warning: categorie check fallback faalde: {e2}")
        if not categorie_check:
            flash('Ongeldige categorie geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Haal bestaande klacht met bijlages
        klacht_get_resp = supabase.table("klacht").select("*").eq("klacht_id", klacht_id).execute()
        existing_bijlages_raw = None
        klacht_row = {}
        klant_id_existing = None
        if klacht_get_resp.data and len(klacht_get_resp.data) > 0:
            klacht_row = klacht_get_resp.data[0]
            existing_bijlages_raw = klacht_row.get('bijlages')
            klant_id_existing = klacht_row.get('klant_id')

        # Converteer opgeslagen string naar lijst van dicts voor bewerking
        existing_bijlages = normalize_bijlages(existing_bijlages_raw)

        # 1) Verwijder aangevinkte bijlages
        # We verwachten een door komma's gescheiden lijst van URL-strings in 'deleted_bijlages' (via template JS)
        deleted_urls_csv = request.form.get('deleted_bijlages', '')
        deleted_urls = [x for x in deleted_urls_csv.split(',') if x.strip()] if deleted_urls_csv else []
        
        if deleted_urls:
            # Delete the file from storage
            for url in deleted_urls:
                delete_file_from_storage(url)
            
            # Filter de te behouden bijlages: alleen de items wiens URL NIET in de deleted_urls lijst zit
            # We filteren op het URL veld van de dict die normalize_bijlages heeft gemaakt
            existing_bijlages = [b for b in existing_bijlages if b.get('url') not in deleted_urls]

        # 2) Upload nieuwe bijlages
        new_files = request.files.getlist('new_bijlages')
        if new_files:
            for nf in new_files:
                if nf and nf.filename:
                    # upload_file_to_storage retourneert een dict met de URL
                    uploaded = upload_file_to_storage(nf, store_in_db=STORE_FILES_IN_DB)
                    if uploaded:
                        existing_bijlages.append(uploaded)

        # Ensure referenced artikel/order rows exist before persisting the complaint
        artikelnummer = ensure_product_exists(artikelnummer, None)
        order_nummer = ensure_order_exists(order_nummer, klant_id_existing)

        # Build update_data - CONVERTEER DE LIJST TERUG NAAR DE OPGESLAGEN STRING/TEXT-FORMAAT
        serialized_bijlages = serialize_bijlages_for_db(existing_bijlages if existing_bijlages else None)
        
        update_data = {
            'order_nummer': order_nummer or None,
            'artikelnummer': safe_int(artikelnummer) if artikelnummer else None,
            'aantal_eenheden': safe_int(aantal_eenheden) if aantal_eenheden else None,
            'categorie_id': int(categorie_id),
            'mogelijke_oorzaak': mogelijke_oorzaak or None,
            'klacht_omschrijving': klacht_omschrijving or None,
            'opmerking': request.form.get('opmerking') or None,
            'businessunit_id': bu_id if bu_id is not None else klacht_row.get('businessunit_id'),
            'datum_laatst_bewerkt': datetime.utcnow().isoformat(),
            'bijlages': serialized_bijlages # <--- Opgeslagen als TEXT (newline URL string)
        }
        # Alleen admin/key user kan verantwoordelijke wijzigen
        if session.get('user_rol') in ('Admin', 'Key user') and verantwoordelijke_id:
            try:
                update_data['verantwoordelijke_id'] = int(verantwoordelijke_id)
            except Exception:
                # keep it safe - ignore invalid int casting
                pass

        # Process status and prioriteit in the update if the user is a manager
        status_in_form = request.form.get('status')
        prioriteit_in_form = request.form.get('prioriteit')

        if is_manager_role():
            if status_in_form:
                update_data['status'] = status_in_form
            # checkbox presence means True; absence => False
            update_data['prioriteit'] = True if prioriteit_in_form else False

        # Now perform the update (single call)
        def missing_column_in_payload(errmsg):
            if not errmsg:
                return None
            m = re.search(r"'([^']+)' column", errmsg)
            return m.group(1) if m else None

        def without_column(payload, colname):
            return {k: v for k, v in payload.items() if k != colname}

        def safe_update(payload):
            try:
                resp = supabase.table("klacht").update(payload).eq("klacht_id", klacht_id).execute()
                err = resp.get('error') if isinstance(resp, dict) else getattr(resp, 'error', None)
                if err:
                    raise Exception(getattr(err, 'message', str(err)))
                return resp
            except Exception as ex:
                msg = str(ex)
                col = missing_column_in_payload(msg)
                if col:
                    cleaned = without_column(payload, col)
                    resp_clean = supabase.table("klacht").update(cleaned).eq("klacht_id", klacht_id).execute()
                    clean_err = resp_clean.get('error') if isinstance(resp_clean, dict) else getattr(resp_clean, 'error', None)
                    if clean_err:
                        raise Exception(getattr(clean_err, 'message', str(clean_err)))
                    return resp_clean
                raise

        response = safe_update(update_data)
        response_error = response.get('error') if isinstance(response, dict) else getattr(response, 'error', None)
        success = response_error is None

        if success:
            # If the status changed and the user is a manager, insert history and send notifications
            if is_manager_role() and status_in_form and status_in_form != old_status:
                try:
                    hist_obj = {
                        'klacht_id': klacht_id,
                        'oude_status': old_status,
                        'nieuwe_status': status_in_form,
                        'gewijzigd_door': session['user_id'],
                        'opmerking': request.form.get('status_opmerking') or None,
                        'datum_wijziging': datetime.utcnow().isoformat()
                    }
                    hist_resp = supabase.table("statushistoriek").insert(hist_obj).execute()
                    check_supabase_response(hist_resp, "insert statushistoriek")
                except Exception as e:
                    print(f"Error inserting statushistoriek: {e}")

            flash('Klacht succesvol bijgewerkt!', 'success')
        else:
            error_msg = 'Er ging iets mis bij het bijwerken van de klacht'
            # Try to extract message from supabase response
            if hasattr(response_error, 'message'):
                error_msg += f": {response_error.message}"
            elif isinstance(response_error, str):
                error_msg += f": {response_error}"
            flash(error_msg, 'error')

        return redirect(url_for('main.klacht_details', klacht_id=klacht_id))
        
    except Exception as e:
        flash(f'Er ging iets mis bij het bijwerken van de klacht: {str(e)}', 'error')
        print(f"Error: {e}")
        traceback.print_exc()
        return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

@main.route('/user/klacht/<int:klacht_id>/verwijderen', methods=['POST'])
def klacht_verwijderen(klacht_id):
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))

    try:
        # fetch complaint to verify permissions and attachments
        kresp = supabase.table("klacht").select("*").eq("klacht_id", klacht_id).execute()
        if not kresp.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        klacht = normalize_klacht_row(kresp.data[0])

        role = normalized_role()
        # owner, admin or key user can delete
        if not (role in ('Admin', 'Key user') or klacht.get('verantwoordelijke_id') == session['user_id']):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # attempt to delete any attachments from storage (safely)
        for bijlage in normalize_bijlages(klacht.get('bijlages')):
            url = bijlage.get('url')
            if url:
                try:
                    delete_file_from_storage(url)
                except Exception as e:
                    print(f"Warning: error deleting attachment from storage: {e}")

        # delete complaint
        del_resp = supabase.table("klacht").delete().eq("klacht_id", klacht_id).execute()
        # Supabase response kan dict of object zijn; check error defensief
        err = None
        if isinstance(del_resp, dict):
            err = del_resp.get('error')
        else:
            err = getattr(del_resp, 'error', None)
        if err:
            flash('Fout bij verwijderen klacht', 'error')
        else:
            flash('Klacht verwijderd', 'success')
    except Exception as e:
        print(f"Error deleting complaint: {e}")
        flash('Er ging iets mis bij verwijderen', 'error')

    return redirect(url_for('main.user_klachten'))

@main.route('/user/klachten/export', methods=['GET'])
def klachten_export():
    if 'user_id' not in session or not is_manager_role():
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.user_klachten'))

    try:
        # fetch all klachten met relationele joins; fallback zonder joins
        try:
            resp = supabase.table("klacht").select(
                "*, klant:klant_id(klantnaam, ondernemingsnummer), "
                "categorie:probleemcategorie(type), "
                "verantwoordelijke:verantwoordelijke_id(naam), "
                "businessunit_ref:businessunit_id(naam)"
            ).execute()
            check_supabase_response(resp, "export: fetching klachten (joins)")
            klachten_raw = resp.data if resp.data else []
        except Exception as e_sel:
            print(f"Warning export: join select failed, fallback. Reason: {e_sel}")
            resp = supabase.table("klacht").select("*").execute()
            check_supabase_response(resp, "export: fetching klachten fallback")
            klachten_raw = resp.data if resp.data else []

        klachten = [normalize_klacht_row(k) for k in klachten_raw]

        # Apply the same filters used in the UI
        klant_id = request.args.get('klant_id')
        categorie_id = request.args.get('categorie_id')
        status = request.args.get('status')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')

        if klant_id:
            klachten = [k for k in klachten if str(k.get('klant_id')) == str(klant_id)]
        if categorie_id:
            klachten = [k for k in klachten if str(k.get('categorie_id')) == str(categorie_id)]
        if status:
            klachten = [k for k in klachten if k.get('status') == status]
        if date_from:
            klachten = [k for k in klachten if k.get('datum_melding') and str(k['datum_melding'])[:10] >= date_from]
        if date_to:
            klachten = [k for k in klachten if k.get('datum_melding') and str(k['datum_melding'])[:10] <= date_to]

        # preload klant en categorie mappings voor ontbrekende info
        klanten_map = {}
        try:
            kmap_resp = supabase.table("klant").select("klant_id, klantnaam, ondernemingsnummer").execute()
            check_supabase_response(kmap_resp, "export: fetch klanten map")
            for r in kmap_resp.data or []:
                if r.get('klant_id') is not None:
                    klanten_map[int(r['klant_id'])] = {
                        'klantnaam': r.get('klantnaam') or '',
                        'ondernemingsnummer': r.get('ondernemingsnummer') or ''
                    }
        except Exception as em:
            print(f"Warning export: could not load klanten map: {em}")
        categorie_map = {}
        try:
            for cat in get_categorieen_list():
                if cat.get('categorie_id') is not None:
                    categorie_map[int(cat['categorie_id'])] = cat.get('type') or ''
        except Exception as cm:
            print(f"Warning export: could not load categorie map: {cm}")

        # Defensive extraction helper
        def safe(k, *keys):
            v = k
            for kk in keys:
                if not v:
                    return ''
                if isinstance(v, dict):
                    v = v.get(kk, '')
                else:
                    return ''
            return v or ''

        # Build Excel workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "Klachten"
        header = [
            'Klacht ID',
            'Verantwoordelijke ID',
            'Verantwoordelijke naam',
            'Klant ID',
            'Klantnaam',
            'Ordernummer',
            'Artikelnummer',
            'Aantal eenheden',
            'Categorie ID',
            'Categorie type',
            'Status',
            'Mogelijke oorzaak',
            'Klacht omschrijving',
            'Prioriteit',
            'Datum melding',
            'Businessunit',
            'Ondernemingsnummer',
            'Bijlagen (URL)',
            'Eerste afbeelding'
        ]
        ws.append(header)

        # set column widths for readability
        widths = [12, 18, 24, 12, 24, 16, 16, 14, 12, 18, 16, 32, 32, 12, 16, 16, 18, 40, 18]
        for i, w in enumerate(widths, start=1):
            ws.column_dimensions[chr(64 + i)].width = w

        for idx, k in enumerate(klachten, start=2):  # data rows start at 2
            try:
                klacht_id = k.get('klacht_id')
                verteg_id = k.get('verantwoordelijke_id') or k.get('vertegenwoordiger_id')
                vertegenw_naam = ''
                if isinstance(k.get('verantwoordelijke'), dict):
                    vertegenw_naam = k.get('verantwoordelijke').get('naam') or ''
                if not vertegenw_naam and isinstance(k.get('vertegenwoordiger'), dict):
                    vertegenw_naam = k.get('vertegenwoordiger').get('naam') or ''
                klant_id_val = k.get('klant_id')
                klantnaam = ''
                ondernemingsnummer = ''
                if isinstance(k.get('klant'), dict):
                    klantnaam = k.get('klant').get('klantnaam') or ''
                    ondernemingsnummer = k.get('klant').get('ondernemingsnummer') or ''
                if (not klantnaam) and klant_id_val in klanten_map:
                    klantnaam = klanten_map[klant_id_val].get('klantnaam') or ''
                    ondernemingsnummer = ondernemingsnummer or klanten_map[klant_id_val].get('ondernemingsnummer') or ''
                cat_id = k.get('categorie_id')
                cat_type = ''
                if isinstance(k.get('categorie'), dict):
                    cat_type = k.get('categorie').get('type') or ''
                if not cat_type and cat_id in categorie_map:
                    cat_type = categorie_map[cat_id]
                prioriteit = k.get('prioriteit')
                
                bijlage_urls = []
                first_image_bytes = None
                
                # normalize_bijlages geeft een lijst van dicts terug met de URL, naam, is_image
                for bijlage in normalize_bijlages(k.get('bijlages')):
                    b_url = bijlage.get('url')
                    if b_url:
                        bijlage_urls.append(b_url)
                        if not first_image_bytes:
                            # Gebruik de is_image flag die we in normalize_bijlages hebben gezet
                            if bijlage.get('is_image'):
                                first_image_bytes = fetch_image_bytes(b_url)

                row = [
                    klacht_id,
                    verteg_id,
                    vertegenw_naam,
                    klant_id_val,
                    klantnaam,
                    k.get('order_nummer') or '',
                    k.get('artikelnummer') or '',
                    k.get('aantal_eenheden') or '',
                    cat_id,
                    cat_type,
                    k.get('status') or '',
                    k.get('mogelijke_oorzaak') or '',
                    k.get('klacht_omschrijving') or k.get('reden_afwijzing') or '',
                    'Ja' if prioriteit else 'Nee',
                    k.get('datum_melding') or '',
                    k.get('businessunit') or get_businessunit_name(k.get('businessunit_id')) or '',
                    ondernemingsnummer or k.get('ondernemingsnummer') or '',
                    "\n".join(bijlage_urls),
                    ''
                ]
                ws.append(row)

                # embed first image if available
                if first_image_bytes:
                    try:
                        img = XLImage(io.BytesIO(first_image_bytes))
                        img.height = 80
                        img.width = 80
                        cell_ref = f"Q{idx}"
                        ws.add_image(img, cell_ref)
                        ws.row_dimensions[idx].height = 70
                    except Exception as ie:
                        print(f"Embed image failed for klacht {klacht_id}: {ie}")
            except Exception as e:
                print(f"Warning: failed to write row for klacht {k.get('klacht_id')}: {e}")

        # Add table styling
        try:
            table = Table(displayName="KlachtenTable", ref=f"A1:Q{ws.max_row}")
            style = TableStyleInfo(name="TableStyleMedium9", showFirstColumn=False, showLastColumn=False, showRowStripes=True, showColumnStripes=False)
            table.tableStyleInfo = style
            ws.add_table(table)
        except Exception as e:
            print(f"Warning: could not add table styling: {e}")

        # Build response with timestamped filename
        bio = io.BytesIO()
        wb.save(bio)
        bio.seek(0)
        filename = f"klachten_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
        response = make_response(bio.getvalue())
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response

    except Exception as e:
        print(f"Exception in klachten_export: {e}")
        traceback.print_exc()
        flash('Er ging iets mis bij het exporteren van klachten', 'error')
        return redirect(url_for('main.user_klachten'))
