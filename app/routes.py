from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response, make_response
import csv
import io
import os
import smtplib
from email.message import EmailMessage
import base64
import json
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
from .category_suggester import suggest_probleemcategorie

main = Blueprint('main', __name__)

# Supabase configuratie
supabase_url = "https://kilpcevxhcwysfllheen.supabase.co"
supabase_key = "sb_secret_Ft6fDkZhNVImBd_cgxFWZg_lCXrcbUa"
supabase = create_client(supabase_url, supabase_key)

# NIEUW: naam van je Storage bucket
BUCKET_NAME = "bijlages"

# Toggle: bestanden in DB opslaan i.p.v. Storage (let op: base64 in DB kan groot worden)
# Voor deze setup gebruiken we enkel Supabase Storage (geen base64 in DB)
STORE_FILES_IN_DB = False  # alleen Storage gebruiken

# Beschikbare businessunits (Productiebedrijf)
BUSINESSUNITS = [
    "Vanca",
    "Vanca Group",
    "Placabois",
    "IWP",
    "Forma",
    "Lamitrans",
]


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
    notify_stale_complaints()
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

# Helper: stuur mail naar admins/key-users bij nieuwe klacht
def notify_new_complaint(businessunit, klacht_id):
    try:
        recipients = get_users_by_roles(['Admin', 'Key user'], businessunit=businessunit)
        emails = [u.get('email') for u in recipients if u.get('email')]
        if not emails:
            return
        try:
            link = url_for('main.klacht_details', klacht_id=klacht_id, _external=True)
        except Exception:
            link = f"/user/klacht/{klacht_id}/details"
        send_email("Nieuwe klacht ingediend", f"Er is een nieuwe klacht #{klacht_id} voor businessunit {businessunit}. Bekijk: {link}", emails)
    except Exception as e:
        print(f"notify_new_complaint error: {e}")

# Helper: stuur mails voor klachten die langer dan 7 dagen op Ingediend staan
def notify_stale_complaints():
    try:
        resp = supabase.table("klacht").select("*").eq("status", "Ingediend").execute()
        check_supabase_response(resp, "stale klachten")
        klachten = resp.data if resp.data else []
        today = date.today()
        for k in klachten:
            try:
                dt_str = k.get('datum_melding')
                if not dt_str:
                    continue
                # parse date yyyy-mm-dd
                dt_date = date.fromisoformat(str(dt_str)[:10])
                if (today - dt_date).days < 7:
                    continue
                bu = k.get('businessunit') or get_businessunit_name(k.get('businessunit_id'))
                klacht_id = k.get('klacht_id')
                # mails naar verantwoordelijke (verantwoordelijke_id), admins/key users van bu
                recipients = []
                verantwoordelijke_id = k.get('verantwoordelijke_id') or k.get('vertegenwoordiger_id')
                if verantwoordelijke_id:
                    user_resp = supabase.table("gebruiker").select("email, businessunit_id").eq("gebruiker_id", safe_int(verantwoordelijke_id)).execute()
                    if user_resp.data and user_resp.data[0].get('email'):
                        recipients.append(user_resp.data[0]['email'])
                recipients += [u.get('email') for u in get_users_by_roles(['Admin', 'Key user'], businessunit=bu) if u.get('email')]
                # dedupe
                recipients = list({r for r in recipients if r})
                if recipients:
                    try:
                        link = url_for('main.klacht_details', klacht_id=klacht_id, _external=True)
                    except Exception:
                        link = f"/user/klacht/{klacht_id}/details"
                    send_email("Reminder: klacht staat 7+ dagen op Ingediend", f"Klacht #{klacht_id} staat langer dan een week op Ingediend. Bekijk: {link}", recipients)
            except Exception as inner:
                print(f"stale notification error for klacht {k.get('klacht_id')}: {inner}")
    except Exception as e:
        print(f"notify_stale_complaints error: {e}")

# Helper: fetch image bytes (from URL or data:) for embedding in Excel
def fetch_image_bytes(url):
    if not url:
        return None
    try:
        if url.startswith('data:'):
            # data URL: data:image/png;base64,...
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

# Helper: fetch businessunit-namen vanuit Supabase (fallback op constante lijst)
def get_businessunits_list():
    try:
        resp = supabase.table("businessunit").select("naam").order("naam").execute()
        check_supabase_response(resp, "fetch businessunits list")
        names = [b.get('naam') for b in (resp.data or []) if b.get('naam')]
        return names if names else BUSINESSUNITS
    except Exception as e:
        print(f"Warning: kon businessunits niet ophalen: {e}")
        return BUSINESSUNITS


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

# Helpers to normalize bijlages stored as TEXT (JSON string) in Supabase
def normalize_bijlages(raw_bijlages):
    """Convert DB value (text with newline-separated urls or legacy json) to list of bijlage dicts."""
    if not raw_bijlages:
        return []
    try:
        data = raw_bijlages
        # Legacy JSON string fallback
        if isinstance(data, str) and data.strip().startswith(("[", "{")):
            try:
                data = json.loads(data)
            except Exception:
                pass

        normalized = []
        if isinstance(data, str):
            candidates = [u for u in data.splitlines() if u.strip()]
            for url in candidates:
                normalized.append({
                    "id": str(uuid.uuid4()),
                    "url": url.strip(),
                    "naam": url.strip().split("/")[-1] if "/" in url else url.strip(),
                    "is_image": url.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))
                })
        elif isinstance(data, dict):
            data = [data]
        if isinstance(data, list):
            for b in data:
                b_copy = dict(b) if isinstance(b, dict) else {"url": b, "naam": str(b)}
                if not b_copy.get('id'):
                    b_copy['id'] = str(uuid.uuid4())
                if b_copy.get('content') and not b_copy.get('url'):
                    ct = b_copy.get('content_type', 'application/octet-stream')
                    b_copy['url'] = f"data:{ct};base64,{b_copy.get('content')}"
                content_type = (b_copy.get('content_type') or '')
                url_lower = (b_copy.get('url') or '').lower()
                b_copy['is_image'] = bool(content_type.startswith('image/') or url_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')))
                normalized.append(b_copy)
        return normalized
    except Exception:
        return []

def serialize_bijlages_for_db(bijlage_list):
    """Store as newline-separated URLs (no JSON string)."""
    if not bijlage_list:
        return None
    try:
        urls = []
        for b in bijlage_list:
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
    # bijlages
    k['bijlages'] = normalize_bijlages(k.get('bijlages'))
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
            query = supabase.table("klacht").select("*, klant:klant_id(klantnaam), categorie:probleemcategorie(type), verantwoordelijke:verantwoordelijke_id(naam), businessunit_ref:businessunit_id(naam)").order("datum_melding", {"ascending": False})
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

        # Als er niets terugkomt, probeer nog één keer een kale select zonder filters
        if not klachten:
            try:
                resp_all = supabase.table("klacht").select("*").execute()
                check_supabase_response(resp_all, "fallback: fetch all klachten on empty result")
                klachten = resp_all.data if resp_all.data else []
            except Exception as e_all:
                print(f"Warning: fallback all complaints failed: {e_all}")
                klachten = []

        # categorieen for filter options (simple select)
        categorieen_resp = supabase.table("probleemcategorie").select("categorie_id, type").execute()
        check_supabase_response(categorieen_resp, "fetching probleemcategorie")
        categorieen = categorieen_resp.data if categorieen_resp.data else []

        klanten_resp = supabase.table("klant").select("klant_id, klantnaam").execute()
        check_supabase_response(klanten_resp, "fetching klanten")
        klanten = klanten_resp.data if klanten_resp.data else []
        klanten_map = {k['klant_id']: k.get('klantnaam') for k in klanten if k.get('klant_id') is not None}

        # dynamic businessunits from table (fallback op constante)
        bu_resp = supabase.table("businessunit").select("naam").execute()
        check_supabase_response(bu_resp, "fetching businessunits for filter")
        dynamic_bu = [b.get('naam') for b in (bu_resp.data or []) if b.get('naam')]
        businessunits_used = dynamic_bu if dynamic_bu else BUSINESSUNITS
        # ensure klantnaam aanwezig
        for k in klachten:
            if not k.get('klant') and k.get('klant_id') in klanten_map:
                k['klant'] = {'klantnaam': klanten_map.get(k.get('klant_id'))}

        return render_template('user_klachten.html',
                               klachten=klachten,
                               categorieen=categorieen,
                               klanten=klanten,
                               businessunits=businessunits_used,
                               vertegenwoordigers=reps_for_filter)
    except Exception as e:
        print(f"Exception in user_klachten: {e}")
        traceback.print_exc()
        flash('Er ging iets mis bij het ophalen van klachten', 'error')
        # Return with empty lists so template can still render
        return render_template('user_klachten.html', klachten=[], categorieen=[], klanten=[], vertegenwoordigers=[])


@main.route('/user/klacht/<int:klacht_id>/details')
def klacht_details(klacht_id):
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))

    try:
        # use relational select to get klant + categorie with one call
        klacht_response = supabase.table("klacht").select("*, klant:klant_id(klantnaam), categorie:probleemcategorie(type), verantwoordelijke:verantwoordelijke_id(naam), businessunit_ref:businessunit_id(naam)").eq("klacht_id", safe_int(klacht_id)).execute()
        check_supabase_response(klacht_response, "fetching single complaint")
        if not klacht_response.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        klacht_data = normalize_klacht_row(klacht_response.data[0])

        # Authorization check - ensure numbers are comparable
        if not can_view_klacht(klacht_data, safe_int(session['user_id']), session.get('user_rol')):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # statushistoriek (defensive)
        try:
            sh_resp = supabase.table("statushistoriek").select("*").eq("klacht_id", safe_int(klacht_id)).order("datum_wijziging", desc=True).execute()
            check_supabase_response(sh_resp, "status historiek")
            statushistoriek = sh_resp.data if sh_resp.data else []
        except Exception as e:
            print(f"Warning: failed to fetch status historiek for {klacht_id}: {e}")
            statushistoriek = []

        # categorieen (for edit dropdown)
        try:
            categorieen_response = supabase.table("probleemcategorie").select("categorie_id, type").execute()
            check_supabase_response(categorieen_response, "fetching categories")
            categorieen = categorieen_response.data if categorieen_response.data else []
        except Exception as e:
            print(f"Warning: could not fetch categorieen: {e}")
            categorieen = []

        # vertegenw if manager/key user
        vertegenw = []
        if normalized_role() in ('Admin', 'Key user'):
            try:
                rep_query = supabase.table("gebruiker").select("gebruiker_id, naam").eq("rol", "User")
                if normalized_role() == 'Key user':
                    my_pid = session.get('businessunit_id')
                    if my_pid:
                        rep_query = rep_query.eq("businessunit_id", safe_int(my_pid))
                reps_resp = rep_query.execute()
                check_supabase_response(reps_resp, "fetching reps")
                vertegenw = reps_resp.data if reps_resp.data else []
            except Exception as e:
                print(f"Warning: could not fetch vertegenw: {e}")
                vertegenw = []
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

        return render_template('klacht_details.html', klacht=klacht_data, klacht_id=klacht_id, categorieen=categorieen, statushistoriek=statushistoriek, vertegenw=vertegenw, businessunits=get_businessunits_list())
    except Exception as e:
        print(f"Exception in klacht_details: {e}")
        traceback.print_exc()
        flash('Er ging iets mis bij het ophalen van de klacht details', 'error')
        return redirect(url_for('main.user_klachten'))

# Helper: upload one file to Supabase Storage OR store base64 in DB and return bijlage dict
def upload_file_to_storage(file_obj, store_in_db=False):
    if not file_obj or not getattr(file_obj, 'filename', None):
        return None
    try:
        safe_name = secure_filename(file_obj.filename)
        unique_id = str(uuid.uuid4())
        unique_name = f"{unique_id}_{safe_name}"
        content_type = getattr(file_obj, 'mimetype', 'application/octet-stream')
        # Ensure pointer at start
        try:
            file_obj.stream.seek(0)
        except Exception:
            pass
        file_bytes = file_obj.read()

        if store_in_db:
            # Store bytes as base64 inside bijlage JSON
            b64 = base64.b64encode(file_bytes).decode('utf-8')
            data_url = f"data:{content_type};base64,{b64}"
            bijlage = {
                "id": unique_id,
                "naam": safe_name,
                "content_type": content_type,
                "content": b64,           # raw base64 stored in DB
                "url": data_url,          # convenience for templates (data: URL)
                "upload_date": datetime.utcnow().isoformat()
            }
            return bijlage
        else:
            # Upload to Supabase Storage
            unique_name = f"{unique_id}_{safe_name}"
            path_in_bucket = f"klachten/{unique_name}"
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
        categorieen_response = supabase.table("probleemcategorie").select("categorie_id, type").execute()
        
        klanten = klanten_response.data if klanten_response.data else []
        categorieen = categorieen_response.data if categorieen_response.data else []
        
    except Exception as e:
        print(f"Error bij ophalen data: {e}")
        klanten = []
        categorieen = []

    suggested_categorie_type = suggest_probleemcategorie(
        request.form.get('reden_afwijzing', '').strip(),
        request.form.get('mogelijke_oorzaak', '').strip()
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
            aantal_eenheden = request.form.get('aantal_eenheden', '').strip()
            mogelijke_oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
            klacht_omschrijving = request.form.get('reden_afwijzing', '').strip()
            ondernemingsnummer = request.form.get('ondernemingsnummer', '').strip()
            businessunit = request.form.get('businessunit', '').strip() or (session.get('businessunit_naam') or '').strip()
            bu_id = resolve_or_create_businessunit(businessunit) if businessunit else None
            print("DEBUG - Form data ontvangen:")
            print(f"  Klant ID: {klant_id}")
            print(f"  Categorie ID: {categorie_id}")
            print(f"  Ordernummer: {order_nummer}")
            print(f"  Artikelnummer: {artikelnummer}")
            print(f"  Aantal eenheden: {aantal_eenheden}")
            print(f"  Businessunit: {businessunit}")

            suggested_categorie_type = suggest_probleemcategorie(klacht_omschrijving, mogelijke_oorzaak)
            suggested_categorie_id = find_categorie_id_by_type(categorieen, suggested_categorie_type)
            if not categorie_id and suggested_categorie_id:
                categorie_id = str(suggested_categorie_id)
            selected_categorie_id = categorie_id or suggested_categorie_id
            
            # Valideer verplichte velden
            if not klant_id and klant_naam:
                # try to resolve klant_id by naam
                try:
                    kresp = supabase.table("klant").select("klant_id").ilike("klantnaam", klant_naam).execute()
                    if kresp.data and len(kresp.data) > 0:
                        klant_id = kresp.data[0].get('klant_id')
                except Exception as ie:
                    print(f"Klant zoeken op naam mislukt: {ie}")
                # if nog steeds geen klant_id: automatisch toevoegen
                if not klant_id:
                    try:
                        insert_resp = supabase.table("klant").insert({"klantnaam": klant_naam}).execute()
                        check_supabase_response(insert_resp, "insert new klant by name")
                        if insert_resp.data and len(insert_resp.data) > 0:
                            klant_id = insert_resp.data[0].get('klant_id')
                    except Exception as ie2:
                        print(f"Nieuwe klant aanmaken mislukt: {ie2}")

            if not klant_id or not categorie_id or not order_nummer or not artikelnummer or not aantal_eenheden or not klacht_omschrijving or not businessunit or not ondernemingsnummer:
                flash('Klant, categorie, ordernummer, artikelnummer, aantal eenheden, businessunit, ondernemingsnummer en klacht omschrijving zijn verplicht', 'error')
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

            # Probeer ondernemingsnummer op te slaan bij de klant (indien beschikbaar)
            if klant_id and ondernemingsnummer:
                try:
                    supabase.table("klant").update({"ondernemingsnummer": ondernemingsnummer}).eq("klant_id", int(klant_id)).execute()
                except Exception as e:
                    print(f"Warning: kon ondernemingsnummer niet opslaan voor klant {klant_id}: {e}")

            # ================== AANGESCHERPT: meerdere bestanden verwerken ==================
            bijlages = []
            # Accept both 'bijlage' and 'bijlage[]' (some clients use bracketed names)
            files = []
            files += request.files.getlist('bijlage') or []
            files += request.files.getlist('bijlage[]') or []
            # Filter out empty file entries and deduplicate by filename+size
            seen_key = set()
            upload_count = 0
            print(f"DEBUG - Received {len(files)} file objects (raw).")
            filtered_files = []
            for f in files:
                if not f or not getattr(f, 'filename', None):
                    continue
                key = (f.filename, getattr(f, 'content_length', None) or f.content_type)
                if key in seen_key:
                    continue
                seen_key.add(key)
                filtered_files.append(f)
            print(f"DEBUG - Filtered to {len(filtered_files)} unique files.")
            # Safely upload each file
            for f in files:
                # keep loop over filtered list to ensure duplicates are not uploaded twice
                pass
            for f in filtered_files:
                try:
                    uploaded = upload_file_to_storage(f, store_in_db=STORE_FILES_IN_DB)
                    if uploaded:
                        bijlages.append(uploaded)
                        upload_count += 1
                        print(f"DEBUG - Uploaded file: {uploaded.get('naam')} ({uploaded.get('url')})")
                except Exception as e:
                    print(f"DEBUG - Error uploading file {f.filename}: {e}")

            if not bijlages:
                bijlages = None
            print(f"DEBUG - Total uploaded bijlages: {len(bijlages) if bijlages else 0}")
            serialized_bijlages = serialize_bijlages_for_db(bijlages)
            # ================== EINDE AANGESCHERPT ==================

            # Alleen datum (zonder uur)
            vandaag = date.today().isoformat()

            # Klacht aanmaken
            nieuwe_klacht = {
                'verantwoordelijke_id': session['user_id'],
                'klant_id': int(klant_id),
                'categorie_id': int(categorie_id),
                'order_nummer': order_nummer,
                'artikelnummer': safe_int(artikelnummer) if artikelnummer else None,
                'aantal_eenheden': safe_int(aantal_eenheden) if aantal_eenheden else None,
                'mogelijke_oorzaak': mogelijke_oorzaak or None,
                'bijlages': serialized_bijlages,              # <--- hier komt de JSON in de tabel als TEXT
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

            def missing_column_in_payload(errmsg):
                col = parse_missing_column(errmsg)
                return col

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
                    col = missing_column_in_payload(msg)
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
                try:
                    nieuw_id = response.data[0].get('klacht_id')
                    notify_new_complaint(businessunit, nieuw_id)
                except Exception as e:
                    print(f"Error sending new complaint notifications: {e}")
                # Notify GM or Sales manager if needed
                # Simple notification: find all users with role Admin/Key user in same bedrijf
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
    data = request.get_json(silent=True) or {}
    klacht_omschrijving = (data.get('klacht_omschrijving') or '').strip()
    mogelijke_oorzaak = (data.get('mogelijke_oorzaak') or '').strip()
    suggested_type = suggest_probleemcategorie(klacht_omschrijving, mogelijke_oorzaak)
    return {"suggested_type": suggested_type}, 200


@main.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    if normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.user_dashboard'))
    notify_stale_complaints()
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

@main.route('/admin/businessunit', methods=['POST'])
def admin_create_businessunit():
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    naam = (request.form.get('naam') or '').strip()
    if not naam:
        flash('Naam van businessunit is verplicht', 'error')
        return redirect(url_for('main.admin_dashboard'))
    try:
        # voorkom dubbele insert: check bestaat
        existing = supabase.table("businessunit").select("businessunit_id").eq("naam", naam).execute()
        check_supabase_response(existing, "check bestaande businessunit")
        if existing.data:
            flash('Businessunit bestaat al', 'info')
            return redirect(url_for('main.admin_dashboard'))
        resp = supabase.table("businessunit").insert({"naam": naam}).execute()
        check_supabase_response(resp, "create businessunit")
        if getattr(resp, "error", None):
            msg = resp.error.message if hasattr(resp.error, "message") else str(resp.error)
            flash(f'Fout bij toevoegen businessunit: {msg}', 'error')
        else:
            flash('Businessunit toegevoegd', 'success')
    except Exception as e:
        print(f"admin_create_businessunit error: {e}")
        flash('Fout bij toevoegen businessunit', 'error')
    return redirect(url_for('main.admin_dashboard'))

@main.route('/keyuser/klacht/<int:klacht_id>/toewijzen', methods=['POST'])
def keyuser_assign_klacht(klacht_id):
    role = normalized_role()
    if 'user_id' not in session or role not in ('Key user','Admin'):
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        # haal klacht op om businessunit te checken
        klacht_resp = supabase.table("klacht").select("businessunit_id, businessunit").eq("klacht_id", klacht_id).execute()
        check_supabase_response(klacht_resp, "fetch klacht for assign")
        klacht_obj = klacht_resp.data[0] if klacht_resp.data else {}
        if role == 'Key user':
            my_bu = session.get('businessunit_naam')
            complaint_bu = klacht_obj.get('businessunit') or get_businessunit_name(klacht_obj.get('businessunit_id'))
            if my_bu and complaint_bu and complaint_bu != my_bu:
                flash('Toegang geweigerd voor deze businessunit', 'error')
                return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        nieuwe_rep = request.form.get('vertegenwoordiger_id')
        if not nieuwe_rep:
            flash('Geen verantwoordelijke geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Check whether the selected user exists
        new_rep_resp = supabase.table("gebruiker").select("*").eq("gebruiker_id", int(nieuwe_rep)).execute()
        if not new_rep_resp.data:
            flash('Gekozen verantwoordelijke niet gevonden', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))
        new_rep = new_rep_resp.data[0]

        # Ensure target has role 'User' (verantwoordelijke)
        if new_rep.get('rol') != 'User':
            flash('Selecteer een verantwoordelijke (User)', 'error')
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
    notify_stale_complaints()

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

# Simple send_email helper (temporarily disabled to avoid sending mails during development)
def send_email(subject, body, to):
    print(f"[EMAIL DISABLED] subject={subject} to={to} body={body}")
    return False

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
        ondernemingsnummer = request.form.get('ondernemingsnummer', '').strip()
        businessunit = request.form.get('businessunit', '').strip() or (session.get('businessunit_naam') or '').strip()
        bu_id = resolve_or_create_businessunit(businessunit) if businessunit else None
        verantwoordelijke_id = request.form.get('vertegenwoordiger_id', '').strip()  # nieuw

        # Valideer verplichte velden
        if not categorie_id or not order_nummer or not artikelnummer or not aantal_eenheden or not klacht_omschrijving:
            flash('Categorie, ordernummer, artikelnummer, aantal eenheden en klacht omschrijving zijn verplicht', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Controleer of categorie_id bestaat
        categorie_check = supabase.table("probleemcategorie").select("categorie_id").eq("categorie_id", int(categorie_id)).execute()
        if not categorie_check.data:
            flash('Ongeldige categorie geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Haal bestaande klacht met bijlages
        klacht_get_resp = supabase.table("klacht").select("*").eq("klacht_id", klacht_id).execute()
        existing_bijlages = []
        klacht_row = {}
        if klacht_get_resp.data and len(klacht_get_resp.data) > 0:
            klacht_row = klacht_get_resp.data[0]
            existing_bijlages = normalize_bijlages(klacht_row.get('bijlages'))
            klant_id_existing = klacht_row.get('klant_id')
            if klant_id_existing and ondernemingsnummer:
                try:
                    supabase.table("klant").update({"ondernemingsnummer": ondernemingsnummer}).eq("klant_id", int(klant_id_existing)).execute()
                except Exception as e:
                    print(f"Warning: kon ondernemingsnummer niet opslaan voor klant {klant_id_existing}: {e}")
        else:
            existing_bijlages = []

        # Defensive: zorg dat elke bestaande bijlage een id heeft
        for bi, b in enumerate(existing_bijlages):
            if isinstance(b, dict) and not b.get('id'):
                existing_bijlages[bi] = {**b, 'id': str(uuid.uuid4())}
            elif not isinstance(b, dict):
                # unexpected format - skip or try convert
                continue

        # 1) Verwijder aangevinkte bijlages
        deleted_ids_csv = request.form.get('deleted_bijlages', '')
        deleted_ids = [x for x in deleted_ids_csv.split(',') if x.strip()] if deleted_ids_csv else []
        if deleted_ids:
            # filter out bijlages whose 'id' is in deleted_ids
            to_remove = [b for b in existing_bijlages if str(b.get('id')) in deleted_ids]
            # Attempt delete from storage for each
            for b in to_remove:
                if b.get('url'):
                    delete_file_from_storage(b.get('url'))
            # Keep only those not deleted
            existing_bijlages = [b for b in existing_bijlages if str(b.get('id')) not in deleted_ids]

        # 2) Upload nieuwe bijlages
        new_files = request.files.getlist('new_bijlages')
        if new_files:
            for nf in new_files:
                if nf and nf.filename:
                    uploaded = upload_file_to_storage(nf, store_in_db=STORE_FILES_IN_DB)
                    if uploaded:
                        existing_bijlages.append(uploaded)

        # Build update_data - include status/prioriteit BEFORE update if manager
        serialized_bijlages = serialize_bijlages_for_db(existing_bijlages if existing_bijlages else None)
        update_data = {
            'order_nummer': order_nummer or None,
            'artikelnummer': safe_int(artikelnummer) if artikelnummer else None,
            'aantal_eenheden': safe_int(aantal_eenheden) if aantal_eenheden else None,
            'categorie_id': int(categorie_id),
            'mogelijke_oorzaak': mogelijke_oorzaak or None,
            'klacht_omschrijving': klacht_omschrijving or None,
            'businessunit_id': bu_id if bu_id is not None else klacht_row.get('businessunit_id'),
            'datum_laatst_bewerkt': datetime.utcnow().isoformat(),
            'bijlages': serialized_bijlages
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

                # On Goedgekeurd -> notify sales managers (rol Admin)
                if status_in_form == 'Goedgekeurd':
                    try:
                        sm_resp = supabase.table("gebruiker").select("email").eq("rol", "Admin").execute()
                        emails = [u['email'] for u in (sm_resp.data or []) if u.get('email')]
                        if emails:
                            send_email("Klacht Goedgekeurd", f"Klacht #{klacht_id} is goedgekeurd.", emails)
                    except Exception as e:
                        print(f"Error sending approve emails: {e}")

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
            url = None
            try:
                if isinstance(bijlage, dict):
                    url = bijlage.get('url')
                elif isinstance(bijlage, str):
                    url = bijlage
                if url:
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
            cmap_resp = supabase.table("probleemcategorie").select("categorie_id, type").execute()
            check_supabase_response(cmap_resp, "export: fetch categorie map")
            for r in cmap_resp.data or []:
                if r.get('categorie_id') is not None:
                    categorie_map[int(r['categorie_id'])] = r.get('type') or ''
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
            'Prioriteit',
            'Datum melding',
            'Businessunit',
            'Ondernemingsnummer',
            'Bijlagen (URL)',
            'Eerste afbeelding'
        ]
        ws.append(header)

        # set column widths for readability
        widths = [12, 18, 24, 12, 24, 16, 16, 14, 12, 18, 12, 12, 16, 16, 18, 40, 18]
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
                if isinstance(k.get('bijlages'), list):
                    for b in k.get('bijlages'):
                        b_url = b.get('url') if isinstance(b, dict) else (b if isinstance(b, str) else '')
                        if b_url:
                            bijlage_urls.append(b_url)
                            if not first_image_bytes:
                                # try fetch image only for first image-like url
                                ct = b.get('content_type') if isinstance(b, dict) else ''
                                if (ct and ct.startswith('image')) or b_url.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')) or b_url.startswith('data:image'):
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
                    'Ja' if prioriteit else 'Nee',
                    k.get('datum_melding') or '',
                    k.get('businessunit') or get_businessunit_name(k.get('businessunit_id')) or '',
                    ondernemingsnummer or k.get('ondernemingsnummer') or '',
                    "\n".join(bijlage_urls)
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
