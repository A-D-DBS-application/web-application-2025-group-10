from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response, make_response, send_from_directory, current_app
import csv
import io
import os
import base64
import uuid
import traceback
import requests
from datetime import datetime, date, timezone
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from openpyxl import Workbook
from openpyxl.drawing.image import Image as XLImage
from openpyxl.worksheet.table import Table, TableStyleInfo
import re
from sqlalchemy.exc import IntegrityError
import requests
from .category_suggester import (
    suggest_probleemcategorie,
    suggest_probleemcategorie_contextual_sqlalchemy,
)
from .models import (
    Businessunit, Klant, Probleemcategorie, Gebruiker, Klacht, 
    StatusHistoriek, Product, Order, db, klacht_status_enum
)
from . import services
from .config import Config

main = Blueprint('main', __name__)

# Lokale file storage directory (fallback, niet meer gebruikt voor nieuwe uploads)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt'}

# Helper: Check Supabase configuratie
def check_supabase_config():
    """Controleer of Supabase configuratie correct is."""
    if not Config.SUPABASE_KEY or Config.SUPABASE_KEY.strip() == '':
        print("ERROR: SUPABASE_KEY is niet ingesteld!")
        return False
    if not Config.SUPABASE_URL or Config.SUPABASE_URL.strip() == '':
        print("ERROR: SUPABASE_URL is niet ingesteld!")
        return False
    return True

# Helper: Genereer publieke URL voor Supabase Storage
def get_supabase_public_url(storage_path):
    """Genereer publieke URL voor bestand in Supabase Storage."""
    return f"{Config.SUPABASE_URL}/storage/v1/object/public/{Config.SUPABASE_STORAGE_BUCKET}/{storage_path}"


@main.route('/')
def index():
    return redirect(url_for('main.login'))

@main.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files (fallback voor oude lokale bestanden)."""
    # Deze route is alleen voor backwards compatibility met oude lokale bestanden
    # Nieuwe uploads gaan naar Supabase Storage en worden via publieke URLs geserveerd
    upload_path = ensure_upload_dir()
    return send_from_directory(upload_path, filename)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Vul alle velden in', 'error')
            return render_template('login.html')
        
        try:
            # Zoek gebruiker via ORM (case-insensitive)
            user = services.get_user_by_email(email.strip())
            
            if user:
                stored_password = user.wachtwoord

                if stored_password and check_password_hash(stored_password, password):
                    # Login succesvol
                    bu_id = user.businessunit_id
                    bu_naam = services.get_businessunit_name(bu_id) if bu_id else ''
                    session['user_id'] = user.gebruiker_id
                    session['user_email'] = user.email
                    session['user_naam'] = user.naam
                    session['user_rol'] = (user.rol or '').strip().capitalize()
                    session['businessunit_id'] = bu_id
                    session['businessunit_naam'] = bu_naam

                    # Redirect naar rol-specifieke dashboard
                    flash('Login succesvol!', 'success')
                    if session['user_rol'] == 'Admin':
                        return redirect(url_for('main.admin_dashboard'))
                    elif session['user_rol'] == 'Key user':
                        return redirect(url_for('main.keyuser_dashboard'))
                    else:
                        return redirect(url_for('main.user_dashboard'))

                # Als plain text (voor testing)
                elif stored_password == password:
                    bu_id = user.businessunit_id
                    bu_naam = services.get_businessunit_name(bu_id) if bu_id else ''
                    session['user_id'] = user.gebruiker_id
                    session['user_email'] = user.email
                    session['user_naam'] = user.naam
                    session['user_rol'] = (user.rol or '').strip().capitalize()
                    session['businessunit_id'] = bu_id
                    session['businessunit_naam'] = bu_naam

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
                # Debug: check of er überhaupt gebruikers in de database zijn
                try:
                    from .models import Gebruiker
                    user_count = db.session.query(Gebruiker).count()
                    print(f"DEBUG: Total users in database: {user_count}")
                    if user_count == 0:
                        flash('Geen gebruikers gevonden in database. Controleer database connectie.', 'error')
                    else:
                        flash('Gebruiker niet gevonden', 'error')
                except Exception as db_error:
                    flash(f'Database fout: {str(db_error)}', 'error')
                    print(f"DEBUG: Database error: {db_error}")
                    traceback.print_exc()
                
        except Exception as e:
            flash('Er ging iets mis bij het inloggen', 'error')
            print(f"Login error: {e}")
            traceback.print_exc()
        
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

# Helper: ensure upload directory exists
def ensure_upload_dir():
    """Zorg dat upload directory bestaat."""
    upload_path = os.path.join(current_app.root_path, '..', UPLOAD_FOLDER)
    os.makedirs(upload_path, exist_ok=True)
    return upload_path

# Helper: normalize businessunit from complaint object
def get_bu_value(obj):
    """Haal businessunit naam op uit klacht object (ORM model of dict)."""
    if not obj:
        return ''
    if isinstance(obj, Klacht):
        if obj.businessunit:
            return obj.businessunit.naam
        return services.get_businessunit_name(obj.businessunit_id) if obj.businessunit_id else ''
    # Legacy dict support
    if obj.get('businessunit'):
        return str(obj.get('businessunit')).strip()
    bu_id = obj.get('businessunit_id')
    if bu_id:
        return services.get_businessunit_name(bu_id) or ''
    return ''

def is_klacht_today(klacht, today_str=None):
    """Check if a complaint was created/entered today."""
    today_str = today_str or date.today().isoformat()
    try:
        if isinstance(klacht, Klacht):
            # ORM object
            dm = klacht.datum_melding
            if dm:
                if hasattr(dm, 'date'):
                    return dm.date().isoformat() == today_str
                else:
                    return str(dm)[:10] == today_str
            return False
        elif isinstance(klacht, dict):
            # Dict support
            dm = str(
                klacht.get('datum_melding')
                or klacht.get('created_at')
                or klacht.get('created')
                or klacht.get('datum')
                or ''
            )
            return dm[:10] == today_str if dm else False
        else:
            return False
    except Exception as e:
        print(f"Warning: is_klacht_today failed: {e}")
        return False

# Helper: fetch image bytes (from URL or data:) for embedding in Excel
def fetch_image_bytes(url):
    """Haal image bytes op voor Excel export."""
    if not url:
        return None
    try:
        if url.startswith('data:'):
            # data URL: data:image/png;base64,... (LEGACY SUPPORT)
            if ';base64,' in url:
                b64 = url.split(';base64,', 1)[1]
                return base64.b64decode(b64)
            return None
        
        # Supabase Storage URL
        if 'supabase.co' in url or 'supabase' in url.lower():
            try:
                import requests
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    return response.content
            except Exception as e:
                print(f"Error fetching from Supabase URL: {e}")
            return None
        
        # Lokale file URL: /uploads/... (fallback voor oude bestanden)
        if url.startswith('/uploads/') or url.startswith('uploads/'):
            upload_path = ensure_upload_dir()
            filename = url.split('/')[-1]
            filepath = os.path.join(upload_path, filename)
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    return f.read()
        return None
    except Exception as e:
        print(f"fetch_image_bytes error: {e}")
    return None

def get_businessunits_list():
    """Haal alle businessunit namen op."""
    return services.get_businessunits_list()

def get_categorieen_list():
    """Haal categorie_id + type op."""
    return services.get_categorieen_list()


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

# Normalizeert de DB-string van URL's naar de structuur die de template verwacht.
def normalize_bijlages(raw_bijlages):
    """
    Converteert de opgeslagen waarde (TEXT met newline-gescheiden URL's)
    naar een lijst van dicts voor de template.
    """
    if not raw_bijlages:
        return []
    
    urls = []
    
    # Behandel de opgeslagen string (newline-gescheiden URL's)
    if isinstance(raw_bijlages, str):
        urls.extend([u.strip() for u in raw_bijlages.splitlines() if u.strip()])
    elif isinstance(raw_bijlages, list):
        for b in raw_bijlages:
            if isinstance(b, dict) and b.get("url"):
                urls.append(b["url"])
            elif isinstance(b, str):
                urls.append(b)
                
    # Filter op unieke, geldige URL-strings en converteer naar template-dicts
    normalized = []
    unique_urls = set()
    for url in urls:
        if url in unique_urls:
            continue
        unique_urls.add(url)
        
        url_lower = url.lower()
        # Check of het een image is: data URL, extensie, of Supabase URL met image extensie
        is_img = (url.startswith('data:image') or 
                 url_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')) or
                 ('supabase' in url_lower and any(ext in url_lower for ext in ['.png', '.jpg', '.jpeg', '.gif', '.webp'])))
        
        # Extract bestandsnaam uit URL
        if '/' in url:
            naam = url.split("/")[-1]
            # Als Supabase URL, probeer bestandsnaam uit path te halen
            if 'supabase' in url_lower and '/' in url:
                # Format: .../public/bucket/path/to/filename.ext
                parts = url.split('/')
                # Zoek naar het laatste deel met een extensie
                for part in reversed(parts):
                    if any(part.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf']):
                        naam = part
                        break
        else:
            naam = url
        
        normalized.append({
            "id": str(uuid.uuid4()),
            "url": url,
            "naam": naam,
            "is_image": is_img
        })
        
    return normalized

def serialize_bijlages_for_db(bijlage_list):
    """Sla op als newline-gescheiden URL's (eenvoudige TEXT-opslag)."""
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

def klacht_to_dict(klacht):
    """Converteer Klacht ORM object naar dict voor templates."""
    if not klacht:
        return {}
    if isinstance(klacht, dict):
        # Al een dict, gebruik normalize voor legacy support
        k = dict(klacht)
        # Zorg dat datum_melding een string is als het een datetime object is
        if k.get('datum_melding') and hasattr(k['datum_melding'], 'isoformat'):
            k['datum_melding'] = k['datum_melding'].isoformat()
        if k.get('datum_laatst_bewerkt') and hasattr(k['datum_laatst_bewerkt'], 'isoformat'):
            k['datum_laatst_bewerkt'] = k['datum_laatst_bewerkt'].isoformat()
    else:
        # ORM object, converteer naar dict
        k = {
            'klacht_id': klacht.klacht_id,
            'verantwoordelijke_id': klacht.verantwoordelijke_id,
            'klant_id': klacht.klant_id,
            'categorie_id': klacht.categorie_id,
            'order_nummer': klacht.order_nummer,
            'artikelnummer': klacht.artikelnummer,
            'aantal_eenheden': klacht.aantal_eenheden,
            'mogelijke_oorzaak': klacht.mogelijke_oorzaak,
            'bijlages': klacht.bijlages,
            'prioriteit': klacht.prioriteit,
            'status': klacht.status,
            'datum_melding': klacht.datum_melding.isoformat() if klacht.datum_melding else None,
            'klacht_omschrijving': klacht.klacht_omschrijving,
            'opmerking_status_wijziging': klacht.opmerking_status_wijziging,
            'datum_laatst_bewerkt': klacht.datum_laatst_bewerkt.isoformat() if klacht.datum_laatst_bewerkt else None,
            'businessunit_id': klacht.businessunit_id,
        }
        # Relaties (veilig toegang met getattr)
        try:
            if hasattr(klacht, 'verantwoordelijke') and klacht.verantwoordelijke:
                k['verantwoordelijke'] = {'naam': klacht.verantwoordelijke.naam}
        except Exception:
            pass
        
        try:
            if hasattr(klacht, 'klant') and klacht.klant:
                k['klant'] = {'klantnaam': klacht.klant.klantnaam, 'ondernemingsnummer': klacht.klant.ondernemingsnummer}
        except Exception:
            pass
        
        try:
            if hasattr(klacht, 'categorie') and klacht.categorie:
                k['categorie'] = {'type': klacht.categorie.type}
        except Exception:
            pass
        
        try:
            if hasattr(klacht, 'businessunit') and klacht.businessunit:
                k['businessunit'] = klacht.businessunit.naam
        except Exception:
            pass
    
    # Legacy field mappings voor templates
    k['vertegenwoordiger_id'] = k.get('verantwoordelijke_id')
    k['reden_afwijzing'] = k.get('klacht_omschrijving')
    k['opmerking'] = k.get('opmerking_status_wijziging')
    if k.get('verantwoordelijke') and not k.get('vertegenwoordiger'):
        k['vertegenwoordiger'] = k.get('verantwoordelijke')
    
    # Businessunit naam
    if not k.get('businessunit'):
        k['businessunit'] = get_bu_value(klacht) if isinstance(klacht, Klacht) else services.get_businessunit_name(k.get('businessunit_id'))
    
    return k
@main.route('/user/klachten')
def user_klachten():
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))

    role = normalized_role()
    sort_order = request.args.get('sort_order', 'nieuwste')
    try:
        # Haal klachten op via ORM met eager loading van relaties
        user_id = safe_int(session['user_id'])
        bu_id = session.get('businessunit_id')
        
        # Eager load relaties om N+1 queries te voorkomen
        from sqlalchemy.orm import joinedload
        base_query = db.session.query(Klacht).options(
            joinedload(Klacht.verantwoordelijke),
            joinedload(Klacht.klant),
            joinedload(Klacht.categorie),
            joinedload(Klacht.businessunit)
        )
        
        # Debug: check role and user info
        print(f"DEBUG: Role={role}, user_id={user_id}, bu_id={bu_id}")
        
        # Rol-gebaseerde filtering
        if role == 'User':
            klachten_raw = base_query.filter_by(verantwoordelijke_id=user_id).all()
            print(f"DEBUG: User role - Found {len(klachten_raw)} klachten for user_id={user_id}")
        elif role == 'Key user' and bu_id:
            klachten_raw = base_query.filter_by(businessunit_id=bu_id).all()
            print(f"DEBUG: Key user role - Found {len(klachten_raw)} klachten for bu_id={bu_id}")
        else:
            # Admin of andere rollen: toon alle klachten
            klachten_raw = base_query.order_by(Klacht.datum_melding.desc()).all()
            print(f"DEBUG: Admin/Other role - Found {len(klachten_raw)} klachten (all)")
        
        # Sorteer (veilig voor timezone-aware en naive datetimes)
        def safe_sort_key(k):
            dm = k.datum_melding
            if dm is None:
                # Gebruik een ver verleden tijd als fallback (timezone-naive)
                return datetime(1900, 1, 1)
            # Normaliseer naar UTC als timezone-aware, anders gebruik zoals het is
            if hasattr(dm, 'tzinfo') and dm.tzinfo is not None:
                # Timezone-aware: converteer naar UTC en verwijder timezone info voor vergelijking
                return dm.astimezone(timezone.utc).replace(tzinfo=None)
            return dm
        
        if sort_order == 'oudste':
            klachten_raw = sorted(klachten_raw, key=safe_sort_key, reverse=False)
        else:
            klachten_raw = sorted(klachten_raw, key=safe_sort_key, reverse=True)
        
        # Converteer naar dicts
        print(f"DEBUG: Converting {len(klachten_raw)} klachten to dicts...")
        klachten = []
        for k in klachten_raw:
            try:
                klacht_dict = klacht_to_dict(k)
                klachten.append(klacht_dict)
            except Exception as e:
                print(f"DEBUG: Error converting klacht {k.klacht_id}: {e}")
                import traceback
                traceback.print_exc()
        
        print(f"DEBUG: Successfully converted {len(klachten)} klachten")
        
        # Verantwoordelijken voor filter
        rep_map = {}
        reps_for_filter = []
        try:
            rep_ids = list(set([k.verantwoordelijke_id for k in klachten_raw if k.verantwoordelijke_id]))
            if rep_ids:
                reps = db.session.query(Gebruiker).filter(Gebruiker.gebruiker_id.in_(rep_ids)).all()
                rep_map = {r.gebruiker_id: r.naam for r in reps}
                reps_for_filter = [{'id': r.gebruiker_id, 'naam': r.naam} for r in reps]
                reps_for_filter = sorted(reps_for_filter, key=lambda x: x['naam'].lower())
        except Exception as e:
            print(f"Warning: verantwoordelijke info kon niet geladen worden: {e}")
        
        # Apply filters from GET params
        klant_id = request.args.get('klant_id')
        klant_naam = request.args.get('klant_naam')
        if not klant_id and klant_naam:
            klant = services.get_klant_by_name(klant_naam)
            if klant:
                klant_id = klant.klant_id
            else:
                # Klantnaam ingevuld maar niet gevonden in systeem:
                # toon expliciet geen resultaten voor deze filter
                klachten = []
        
        categorie_id = request.args.get('categorie_id')
        status = request.args.get('status')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        businessunit_filter = (request.args.get('businessunit') or '').strip()
        verantwoordelijke_naam = (request.args.get('verantwoordelijke_naam') or request.args.get('vertegenwoordiger_naam') or '').strip()
        high_priority = (request.args.get('high_priority') or '').lower() in ('true', '1', 'on')
        # Check filters_applied (veilig voor alle types, geen iteratie over datetime)
        filters_applied = bool(
            klant_id or klant_naam or categorie_id or status or 
            date_from or date_to or businessunit_filter or 
            verantwoordelijke_naam or high_priority
        )

        # Filter klachten
        if klant_id:
            klachten = [k for k in klachten if str(k.get('klant_id')) == str(klant_id)]
        if categorie_id:
            klachten = [k for k in klachten if str(k.get('categorie_id')) == str(categorie_id)]
        if status:
            klachten = [k for k in klachten if k.get('status') == status]
        if verantwoordelijke_naam and role in ('Admin', 'Key user'):
            name_lower = verantwoordelijke_naam.lower()
            def match_rep(k):
                rep_id = k.get('verantwoordelijke_id')
                nm = rep_map.get(rep_id, '') if rep_id else ''
                if not nm and k.get('verantwoordelijke'):
                    nm = k['verantwoordelijke'].get('naam', '')
                return name_lower in nm.lower()
            klachten = [k for k in klachten if match_rep(k)]
        if date_from:
            klachten = [k for k in klachten if k.get('datum_melding') and str(k['datum_melding'])[:10] >= date_from]
        if date_to:
            klachten = [k for k in klachten if k.get('datum_melding') and str(k['datum_melding'])[:10] <= date_to]
        
        bu_session = (session.get('businessunit_naam') or '').strip()
        for k in klachten:
            if not k.get('businessunit'):
                k['businessunit'] = services.get_businessunit_name(k.get('businessunit_id')) or bu_session

        # Key user filtering: alleen klachten van eigen businessunit
        if role == 'Key user' and bu_session:
            klachten = [k for k in klachten if (k.get('businessunit') == bu_session)]
            print(f"DEBUG: After Key user businessunit filter, {len(klachten)} klachten remaining")
        else:
            print(f"DEBUG: After businessunit processing, {len(klachten)} klachten remaining")

        if businessunit_filter and role != 'Key user':
            klachten = [k for k in klachten if k.get('businessunit') == businessunit_filter.strip()]

        if high_priority:
            klachten = [k for k in klachten if k.get('prioriteit')]

        # Normalizeer bijlages
        for k in klachten:
            k['bijlages'] = normalize_bijlages(k.get('bijlages'))

        print(f"DEBUG: After all filters, {len(klachten)} klachten remaining")
        print(f"DEBUG: Role={role}, user_id={user_id}, bu_id={bu_id}")

        # Haal filter opties op
        categorieen = get_categorieen_list()
        klanten_all = services.get_all_klanten()
        klanten = [{'klant_id': k.klant_id, 'klantnaam': k.klantnaam} for k in klanten_all]
        businessunits_used = get_businessunits_list()
        status_options = get_status_options()

        print(f"DEBUG: Rendering template with {len(klachten)} klachten")
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
        error_msg = str(e)
        error_type = type(e).__name__
        print(f"EXCEPTION in user_klachten: {error_type}: {error_msg}")
        import traceback
        print("Full traceback:")
        traceback.print_exc()
        # Toon meer details in development mode
        error_detail = f"{error_type}: {error_msg[:150]}"
        flash(f'Er ging iets mis bij het ophalen van klachten: {error_detail}', 'error')
        # Probeer in ieder geval lege lijst te tonen in plaats van crash
        print(f"DEBUG: Exception occurred, returning empty list")
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
        # Haal klacht op via ORM
        klacht = services.get_klacht_by_id(klacht_id)
        if not klacht:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        klacht_data = klacht_to_dict(klacht)

        # Authorization check
        if not can_view_klacht(klacht_data, safe_int(session['user_id']), session.get('user_rol')):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # Statushistoriek
        statushistoriek_raw = services.get_statushistoriek_for_klacht(klacht_id)
        statushistoriek = [
            {
                'status_id': sh.status_id,
                'oude_status': sh.oude_status,
                'nieuwe_status': sh.nieuwe_status,
                'gewijzigd_door': sh.gewijzigd_door,
                'opmerking': sh.opmerking,
                'datum_wijziging': sh.datum_wijziging.isoformat() if sh.datum_wijziging else None
            }
            for sh in statushistoriek_raw
        ]

        # Categorieën voor dropdown
        categorieen = get_categorieen_list()

        # Klanten, orders en producten voor datalists
        klanten = []
        try:
            klanten_all = services.get_all_klanten()
            klanten = [{'klant_id': k.klant_id, 'klantnaam': k.klantnaam} for k in klanten_all]
        except Exception as e:
            print(f"Error bij ophalen klanten: {e}")
            klanten = []

        try:
            orders_all = services.get_all_orders()
            orders = []
            for o in orders_all:
                try:
                    klantnaam = None
                    if getattr(o, 'klant_id', None):
                        k = services.get_klant_by_id(o.klant_id)
                        klantnaam = k.klantnaam if k else ''
                except Exception:
                    klantnaam = ''
                orders.append({'order_nummer': o.order_nummer, 'klant_id': o.klant_id, 'klantnaam': klantnaam})
            producten_all = services.get_all_products()
            producten = [{'artikel_nr': p.artikel_nr, 'naam': p.naam} for p in producten_all]
        except Exception as e:
            print(f"Error bij ophalen orders/producten: {e}")
            orders = []
            producten = []

        # Vertegenwoordigers voor toewijzing (alleen Admin/Key user)
        vertegenw = []
        current_role = normalized_role()
        if current_role in ('Admin', 'Key user'):
            try:
                users = services.get_all_users()
                vertegenw = [{'gebruiker_id': u.gebruiker_id, 'naam': u.naam, 'rol': u.rol, 'businessunit_id': u.businessunit_id} for u in users]
                vertegenw = sorted(vertegenw, key=lambda u: (u.get('naam') or '').lower())
            except Exception as e:
                print(f"Warning: could not fetch vertegenw: {e}")
                vertegenw = []
        
        # Normalizeer bijlages
        raw_bijlages = klacht_data.get('bijlages')
        print(f"DEBUG: Raw bijlages voor klacht {klacht_id}: {raw_bijlages}")
        normalized_bijlages = normalize_bijlages(raw_bijlages)
        print(f"DEBUG: Genormaliseerde bijlages voor klacht {klacht_id}: {normalized_bijlages}")
        klacht_data['bijlages'] = normalized_bijlages

        return render_template(
            'klacht_details.html',
            klacht=klacht_data,
            klacht_id=klacht_id,
            categorieen=categorieen,
            statushistoriek=statushistoriek,
            vertegenw=vertegenw,
            klanten=klanten,
            orders=orders,
            producten=producten,
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
    """Upload file naar Supabase Storage en retourneer bijlage dict met URL."""
    if not file_obj or not getattr(file_obj, 'filename', None):
        return None
    try:
        safe_name = secure_filename(file_obj.filename)
        unique_id = str(uuid.uuid4())
        
        # Bepaal directory structuur (zoals in Supabase bucket)
        bu_part = secure_filename(businessunit_name.replace(' ', '_')) if businessunit_name else "OnbekendeBU"
        if klant_naam:
            klant_part = secure_filename(klant_naam).replace(' ', '_')[:15]
        else:
            klant_part = "OnbekendeKlant"
        klacht_part = f"Klacht_{klacht_id}" if klacht_id else "TEMP"
        
        # Bestandsnaam met UUID
        filename = f"{unique_id}_{safe_name}"
        
        # Pad in Supabase Storage bucket
        storage_path = f"{bu_part}/{klant_part}/{klacht_part}/{filename}"
        
        content_type = getattr(file_obj, 'mimetype', 'application/octet-stream')
        
        # Lees file bytes
        try:
            file_obj.stream.seek(0)
        except Exception:
            pass
        
        if hasattr(file_obj, 'read'):
            file_bytes = file_obj.read()
        else:
            file_bytes = file_obj.get('bytes', b'')
        
        # Upload naar Supabase Storage via directe HTTP request
        if check_supabase_config():
            try:
                print(f"DEBUG: Probeer bestand te uploaden naar Supabase: {storage_path}")
                print(f"DEBUG: Bucket: {Config.SUPABASE_STORAGE_BUCKET}, File size: {len(file_bytes)} bytes")
                
                # Supabase Storage API endpoint voor upload
                upload_url = f"{Config.SUPABASE_URL}/storage/v1/object/{Config.SUPABASE_STORAGE_BUCKET}/{storage_path}"
                
                # Headers voor Supabase Storage API
                headers = {
                    "Authorization": f"Bearer {Config.SUPABASE_KEY}",
                    "Content-Type": content_type,
                    "x-upsert": "false"  # Voorkom overschrijven van bestaande bestanden
                }
                
                # Upload bestand via HTTP POST
                response = requests.post(
                    upload_url,
                    data=file_bytes,
                    headers=headers,
                    timeout=30
                )
                
                print(f"DEBUG: Upload response status: {response.status_code}")
                print(f"DEBUG: Upload response: {response.text[:200] if response.text else 'No response body'}")
                print(f"DEBUG: Gebruikte key type: {'SERVICE_ROLE' if Config.SUPABASE_SERVICE_KEY else 'ANON (fallback - uploads kunnen falen!)'}")
                
                if response.status_code in [200, 201]:
                    # Haal publieke URL op
                    public_url = get_supabase_public_url(storage_path)
                    print(f"DEBUG: Publieke URL gegenereerd: {public_url}")
                    
                    bijlage = {
                        "id": unique_id,
                        "url": public_url,  # Publieke Supabase URL
                        "naam": safe_name,
                        "content_type": content_type,
                        "upload_date": datetime.utcnow().isoformat(),
                        "storage_path": storage_path  # Bewaar pad voor verwijderen
                    }
                    print(f"SUCCESS: Bestand succesvol geüpload naar Supabase Storage: {storage_path}")
                    return bijlage
                else:
                    error_response = response.text
                    if "row-level security policy" in error_response.lower():
                        error_msg = (
                            f"Supabase Storage upload mislukt: Row Level Security (RLS) policy blokkeert upload. "
                            f"Oplossing: Gebruik de service_role key in plaats van anon key, of pas de RLS policies aan in Supabase Dashboard. "
                            f"Status: {response.status_code}, Response: {error_response}"
                        )
                    else:
                        error_msg = f"Supabase upload failed met status {response.status_code}: {error_response}"
                    print(f"ERROR: {error_msg}")
                    raise Exception(error_msg)
                    
            except Exception as e:
                print(f"ERROR: Supabase upload error: {e}")
                print(f"ERROR: Error type: {type(e).__name__}")
                traceback.print_exc()
                # Geen fallback meer - gooi error door zodat gebruiker weet dat upload faalde
                raise Exception(f"Upload naar Supabase Storage mislukt: {str(e)}")
        else:
            # Geen fallback meer - gooi error als configuratie niet correct is
            error_msg = "Supabase configuratie niet correct. Upload naar Supabase Storage is vereist."
            print(f"ERROR: {error_msg}")
            raise Exception(error_msg)
            
    except Exception as e:
        print(f"Upload error: {e}")
        traceback.print_exc()
        return None

# Lokale fallback functie verwijderd - uploads moeten altijd naar Supabase Storage gaan

# Helper: delete file from Supabase Storage (of lokale storage als fallback)
def delete_file_from_storage(file_url):
    """Verwijder file uit Supabase Storage of lokale storage."""
    try:
        if not file_url:
            return None
        # Skip data URLs (legacy)
        if file_url.startswith('data:'):
            return None
        
        # Check of het een Supabase URL is
        if 'supabase.co' in file_url or 'supabase' in file_url.lower():
            # Parse Supabase URL om storage path te krijgen
            # Format: https://[project].supabase.co/storage/v1/object/public/bijlages/path/to/file
            try:
                # Extract path na /public/bijlages/
                if '/public/' in file_url:
                    path_part = file_url.split('/public/')[1]
                    if '/' in path_part:
                        # Skip bucket name (eerste deel na /public/)
                        parts = path_part.split('/', 1)
                        storage_path = parts[1] if len(parts) > 1 else path_part
                    else:
                        storage_path = path_part
                    
                    # Verwijder via directe HTTP DELETE request
                    if check_supabase_config():
                        delete_url = f"{Config.SUPABASE_URL}/storage/v1/object/{Config.SUPABASE_STORAGE_BUCKET}/{storage_path}"
                        headers = {
                            "Authorization": f"Bearer {Config.SUPABASE_KEY}"
                        }
                        response = requests.delete(delete_url, headers=headers, timeout=30)
                        
                        if response.status_code in [200, 204]:
                            print(f"SUCCESS: Bestand verwijderd uit Supabase Storage: {storage_path}")
                            return True
                        else:
                            print(f"ERROR: Supabase delete failed met status {response.status_code}: {response.text}")
                            return None
            except Exception as e:
                print(f"ERROR: Supabase delete error: {e}")
                traceback.print_exc()
                return None
        
        # Fallback: lokale storage verwijderen
        if file_url.startswith('/uploads/'):
            file_url = file_url[1:]  # Remove leading /
        
        if file_url.startswith('uploads/'):
            upload_path = ensure_upload_dir()
            filepath = os.path.join(upload_path, file_url.replace('uploads/', ''))
            if os.path.exists(filepath):
                os.remove(filepath)
                return True
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
    
    # Haal klanten, orders, producten en categorieën op voor dropdowns
    try:
        klanten_all = services.get_all_klanten()
        klanten = [{'klant_id': k.klant_id, 'klantnaam': k.klantnaam} for k in klanten_all]
        categorieen = get_categorieen_list()
        orders_all = services.get_all_orders()
        orders = []
        for o in orders_all:
            try:
                klantnaam = None
                if getattr(o, 'klant_id', None):
                    k = services.get_klant_by_id(o.klant_id)
                    klantnaam = k.klantnaam if k else ''
            except Exception:
                klantnaam = ''
            orders.append({'order_nummer': o.order_nummer, 'klant_id': o.klant_id, 'klantnaam': klantnaam})
        producten_all = services.get_all_products()
        producten = [{'artikel_nr': p.artikel_nr, 'naam': p.naam} for p in producten_all]
    except Exception as e:
        print(f"Error bij ophalen data: {e}")
        klanten = []
        categorieen = []
        orders = []
        producten = []

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
            aantal_eenheden = request.form.get('aantal_eenheden', '').strip()
            mogelijke_oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
            klacht_omschrijving = request.form.get('reden_afwijzing', '').strip()
            
            # De businessunit naam is cruciaal voor het pad, zorg dat deze correct is
            businessunit = request.form.get('businessunit', '').strip() or (session.get('businessunit_naam') or '').strip()
            bu_id = services.resolve_or_create_businessunit(businessunit) if businessunit else None
            
            # 1. Bepaal Klant ID en Klantnaam - klant moet bestaan (geen automatische creatie)
            klant_naam_used = klant_naam
            if not klant_id:
                if klant_naam:
                    # Probeer klant_id op te lossen via ORM
                    klant = services.get_klant_by_name(klant_naam)
                    if klant:
                        klant_id = klant.klant_id
                    else:
                        flash('Klant niet gevonden. Kies een bestaande klant uit de lijst.', 'error')
                        # Zorg dat suggestion/categorie waarden behouden blijven
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
                            orders=orders,
                            producten=producten,
                            businessunits=get_businessunits_list(),
                            suggested_categorie_id=suggested_categorie_id,
                            suggested_categorie_type=suggested_categorie_type,
                            selected_categorie_id=selected_categorie_id
                        )
                else:
                    flash('Klant is verplicht. Kies een bestaande klant uit de lijst.', 'error')
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
                        orders=orders,
                        producten=producten,
                        businessunits=get_businessunits_list(),
                        suggested_categorie_id=suggested_categorie_id,
                        suggested_categorie_type=suggested_categorie_type,
                        selected_categorie_id=selected_categorie_id
                    )
            elif klant_id and not klant_naam:
                # Haal de naam op als we alleen het ID hebben
                klant = services.get_klant_by_id(klant_id)
                if klant:
                    klant_naam_used = klant.klantnaam
            
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

            # 4. Valideer dat order en product bestaan (klachten alleen voor bestaande orders/artikelen)
            order_obj = services.get_order_by_nummer(order_nummer)
            product_obj = services.get_product_by_artikelnummer(artikelnummer)
            if not order_obj:
                flash('Ordernummer niet gevonden. Kies een bestaand ordernummer uit de lijst.', 'error')
                return render_template(
                    'klacht_aanmaken.html',
                    user_naam=session.get('user_naam'),
                    klanten=klanten,
                    categorieen=categorieen,
                    orders=orders,
                    producten=producten,
                    businessunits=get_businessunits_list(),
                    suggested_categorie_id=suggested_categorie_id,
                    suggested_categorie_type=suggested_categorie_type,
                    selected_categorie_id=selected_categorie_id
                )
            # Controleer of de klant van het gekozen order overeenkomt met de opgegeven klant
            try:
                order_klant_id = getattr(order_obj, 'klant_id', None)
                if order_klant_id is not None and klant_id:
                    if str(order_klant_id) != str(klant_id):
                        flash('Geselecteerde klant en ordernummer komen niet overeen.', 'error')
                        return render_template(
                            'klacht_aanmaken.html',
                            user_naam=session.get('user_naam'),
                            klanten=klanten,
                            categorieen=categorieen,
                            orders=orders,
                            producten=producten,
                            businessunits=get_businessunits_list(),
                            suggested_categorie_id=suggested_categorie_id,
                            suggested_categorie_type=suggested_categorie_type,
                            selected_categorie_id=selected_categorie_id
                        )
            except Exception:
                pass
            if not product_obj:
                flash('Artikelnummer niet gevonden. Kies een bestaand artikelnummer uit de lijst.', 'error')
                return render_template(
                    'klacht_aanmaken.html',
                    user_naam=session.get('user_naam'),
                    klanten=klanten,
                    categorieen=categorieen,
                    orders=orders,
                    producten=producten,
                    businessunits=get_businessunits_list(),
                    suggested_categorie_id=suggested_categorie_id,
                    suggested_categorie_type=suggested_categorie_type,
                    selected_categorie_id=selected_categorie_id
                )
            # Maak nieuwe klacht via ORM
            nieuwe_klacht = Klacht(
                verantwoordelijke_id=safe_int(session['user_id']),
                klant_id=int(klant_id),
                categorie_id=int(categorie_id),
                order_nummer=order_nummer,
                artikelnummer=safe_int(artikelnummer) if artikelnummer else None,
                aantal_eenheden=safe_int(aantal_eenheden) if aantal_eenheden else None,
                mogelijke_oorzaak=mogelijke_oorzaak or None,
                bijlages=None,  # Eerst op None, upload komt later
                prioriteit=False,
                status='Ingediend',
                datum_melding=datetime.now(),
                klacht_omschrijving=klacht_omschrijving,
                businessunit_id=bu_id,
                opmerking_status_wijziging=None,
                datum_laatst_bewerkt=datetime.now()
            )
            
            db.session.add(nieuwe_klacht)
            db.session.commit()
            nieuw_id = nieuwe_klacht.klacht_id
            
            # 5. Bestanden uploaden met de nieuwe Klacht ID
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
                        store_in_db=False,
                        klacht_id=nieuw_id,
                        klant_naam=klant_naam_used,
                        klant_id_val=klant_id,
                        businessunit_name=businessunit
                    )
                    if uploaded:
                        bijlages_uploaded.append(uploaded)
                except Exception as e:
                    error_msg = f"Fout bij uploaden van bestand '{file_data['filename']}': {str(e)}"
                    print(f"ERROR - {error_msg}")
                    flash(error_msg, 'error')
                    # Stop de hele operatie als upload faalt - geen lokale fallback meer
                    raise Exception(f"Upload van bijlage mislukt: {str(e)}")
            
            # 6. Update de klacht met bijlage-URL's (als er bijlages zijn)
            if bijlages_uploaded:
                serialized_bijlages = serialize_bijlages_for_db(bijlages_uploaded)
                nieuwe_klacht.bijlages = serialized_bijlages
                db.session.commit()
            
            # 7. Succesmelding en redirect naar dashboard
            flash('Klacht succesvol aangemaakt!', 'success')
            # Redirect naar rol-specifieke dashboard
            role = normalized_role()
            if role == 'Admin':
                return redirect(url_for('main.admin_dashboard'))
            elif role == 'Key user':
                return redirect(url_for('main.keyuser_dashboard'))
            else:
                return redirect(url_for('main.user_dashboard'))
                
        except Exception as e:
            error_msg = f'Er ging iets mis bij het aanmaken van de klacht: {str(e)}'
            flash(error_msg, 'error')
            print(f"ERROR - Exception: {str(e)}")
    
    return render_template(
        'klacht_aanmaken.html',
        user_naam=session.get('user_naam'),
        klanten=klanten,
        categorieen=categorieen,
        orders=orders,
        producten=producten,
        businessunits=get_businessunits_list(),
        suggested_categorie_id=suggested_categorie_id,
        suggested_categorie_type=suggested_categorie_type,
        selected_categorie_id=selected_categorie_id
    )


@main.route('/suggest-categorie', methods=['POST'])
def suggest_categorie():
    """Server-side categorie suggestie endpoint (retourneert alleen text, geen JSON API)."""
    try:
        omschrijving = request.form.get('klacht_omschrijving', '').strip()
        oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
        businessunit_id = request.form.get('businessunit_id')
        
        bu_id = None
        if businessunit_id:
            try:
                bu_id = int(businessunit_id)
            except (ValueError, TypeError):
                pass
        
        suggested = suggest_categorie_safe(omschrijving, oorzaak, bu_id)
        return suggested or '', 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        print(f"Error in suggest_categorie: {e}")
        return '', 200, {'Content-Type': 'text/plain; charset=utf-8'}


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
        # Tel gebruikers via ORM
        try:
            total_gebruikers = db.session.query(Gebruiker).count()
        except Exception as ue:
            print(f"Warning: count gebruikers failed: {ue}")
            total_gebruikers = 0

        # Tel klachten (open) en vandaag via ORM
        try:
            klachten_all = services.get_all_klachten()
            total_klachten = len([k for k in klachten_all if k.status != 'Afgehandeld'])
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
        gebruikers_raw = services.get_all_users()
        gebruikers = []
        for u in gebruikers_raw:
            gebruikers.append({
                'gebruiker_id': u.gebruiker_id,
                'naam': u.naam,
                'email': u.email,
                'rol': u.rol,
                'businessunit_id': u.businessunit_id,
                'businessunit_naam': services.get_businessunit_name(u.businessunit_id) if u.businessunit_id else ''
            })
    except Exception as e:
        print(f"Error fetching users: {e}")
        gebruikers = []
    businessunits_used = get_businessunits_list()
    return render_template('admin_users.html', gebruikers=gebruikers, businessunits=businessunits_used)

# Update role usage when creating users
@main.route('/admin/users', methods=['POST'])
def admin_create_user():
    # Alleen admins mogen gebruikers aanmaken vanuit het beheer scherm
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))

    # Form velden ophalen en normaliseren
    naam = (request.form.get('naam') or '').strip()
    email = (request.form.get('email') or '').strip()
    rol = (request.form.get('rol') or 'User').strip()
    wachtwoord = (request.form.get('wachtwoord') or 'changeme').strip()
    businessunit_raw = (request.form.get('businessunit') or '').strip() or None

    # Basisvalidatie
    if not naam or not email:
        flash('Naam en email zijn verplicht', 'error')
        return redirect(url_for('main.admin_users_page'))
    try:
        # Let op: wachtwoord wordt nu in platte tekst opgeslagen op verzoek
        hashed = wachtwoord
        bu_id = services.resolve_or_create_businessunit(businessunit_raw)
        
        # Check of email al bestaat
        existing = services.get_user_by_email(email)
        if existing:
            flash('Email bestaat al', 'error')
            return redirect(url_for('main.admin_users_page'))
        
        new_user = Gebruiker(
            naam=naam,
            email=email,
            rol=(rol or '').strip().capitalize(),
            wachtwoord=hashed,
            businessunit_id=bu_id
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Gebruiker succesvol aangemaakt', 'success')
    except IntegrityError as ie:
        # Mogelijke sequence desync na data-import: reset sequence en probeer opnieuw
        db.session.rollback()
        try:
            max_id = db.session.query(db.func.max(Gebruiker.gebruiker_id)).scalar() or 0
            # Alleen uitvoeren voor PostgreSQL
            if db.engine.dialect.name == 'postgresql':
                db.session.execute(
                    db.text(
                        "SELECT setval(pg_get_serial_sequence('gebruiker','gebruiker_id'), :newval, true)"
                    ),
                    {'newval': max_id}
                )
                # Maak nieuwe instantie na rollback
                new_user_retry = Gebruiker(
                    naam=naam,
                    email=email,
                    rol=(rol or '').strip().capitalize(),
                    wachtwoord=hashed,
                    businessunit_id=bu_id
                )
                db.session.add(new_user_retry)
                db.session.commit()
                flash('Gebruiker succesvol aangemaakt', 'success')
            else:
                flash('Er ging iets mis bij het aanmaken van de gebruiker (PK conflict)', 'error')
        except Exception as e_reset:
            db.session.rollback()
            print(f"Error resetting gebruiker_id sequence: {e_reset}")
            flash('Er ging iets mis bij het aanmaken van de gebruiker', 'error')
    except Exception as e:
        print(f"Error creating user: {e}")
        db.session.rollback()
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
        user = services.get_user_by_id(user_id)
        if not user:
            flash('Gebruiker niet gevonden', 'error')
            return redirect(url_for('main.admin_users_page'))
        
        if rol:
            user.rol = rol.strip().capitalize()
        if businessunit_raw is not None:
            if str(businessunit_raw).strip() == '':
                user.businessunit_id = None
            else:
                user.businessunit_id = services.resolve_or_create_businessunit(businessunit_raw)
        
        db.session.commit()
        flash('Gebruiker bijgewerkt', 'success')
    except Exception as e:
        print(f"admin_update_user error: {e}")
        db.session.rollback()
        flash('Fout bij bijwerken gebruiker', 'error')
    return redirect(url_for('main.admin_users_page'))

@main.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        user = services.get_user_by_id(user_id)
        if not user:
            flash('Gebruiker niet gevonden', 'error')
            return redirect(url_for('main.admin_users_page'))
        
        # Block deletion when the user still owns open complaints
        open_klachten = db.session.query(Klacht).filter_by(
            verantwoordelijke_id=user_id
        ).filter(Klacht.status.notin_(['Afgehandeld', 'Afgewezen'])).all()
        
        if open_klachten:
            count_open = len(open_klachten)
            flash(f'Kan gebruiker niet verwijderen: er zijn nog {count_open} openstaande klacht(en). Wijs ze eerst toe aan een andere verantwoordelijke.', 'error')
            return redirect(url_for('main.admin_users_page'))

        db.session.delete(user)
        db.session.commit()
        flash('Gebruiker verwijderd', 'success')
    except Exception as e:
        print(f"admin_delete_user error: {e}")
        db.session.rollback()
        flash('Fout bij verwijderen gebruiker', 'error')
    return redirect(url_for('main.admin_users_page'))

@main.route('/admin/businessunits', methods=['GET'])
def admin_businessunits_page():
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        # Toon businessunits gesorteerd op ID, zodat de nieuwe volgorde duidelijk is
        businessunits_raw = db.session.query(Businessunit).order_by(Businessunit.businessunit_id.asc()).all()
        businessunits = [{'businessunit_id': bu.businessunit_id, 'naam': bu.naam} for bu in businessunits_raw]
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
        # Voorkom dubbele insert: check bestaat
        existing = db.session.query(Businessunit).filter_by(naam=naam).first()
        if existing:
            flash('Businessunit bestaat al', 'info')
            return redirect(url_for('main.admin_businessunits_page'))

        # Omdat de PK in de database geen automatische sequence heeft,
        # bepalen we hier handmatig het volgende ID (max + 1).
        max_id = db.session.query(db.func.max(Businessunit.businessunit_id)).scalar() or 0
        new_id = max_id + 1

        new_bu = Businessunit(businessunit_id=new_id, naam=naam)
        db.session.add(new_bu)
        db.session.commit()
        flash('Businessunit toegevoegd', 'success')
    except Exception as e:
        print(f"admin_create_businessunit error: {e}")
        db.session.rollback()
        flash(f'Fout bij toevoegen businessunit: {e}', 'error')
    return redirect(url_for('main.admin_businessunits_page'))

@main.route('/admin/businessunit/<int:businessunit_id>/delete', methods=['POST'])
def admin_delete_businessunit(businessunit_id):
    if 'user_id' not in session or normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        bu = services.get_businessunit_by_id(businessunit_id)
        if not bu:
            flash('Businessunit niet gevonden', 'error')
            return redirect(url_for('main.admin_businessunits_page'))
        
        # Voorkom verwijderen als businessunit nog gekoppeld is
        users_check = db.session.query(Gebruiker).filter_by(businessunit_id=businessunit_id).first()
        if users_check:
            flash('Kan businessunit niet verwijderen: deze is gekoppeld aan een gebruiker.', 'error')
            return redirect(url_for('main.admin_businessunits_page'))

        klachten_check = db.session.query(Klacht).filter_by(businessunit_id=businessunit_id).first()
        if klachten_check:
            flash('Kan businessunit niet verwijderen: verwijder eerst alle klachten die aan deze businessunit gekoppeld zijn.', 'error')
            return redirect(url_for('main.admin_businessunits_page'))

        db.session.delete(bu)
        db.session.commit()
        flash('Businessunit verwijderd', 'success')
    except Exception as e:
        print(f"admin_delete_businessunit error: {e}")
        db.session.rollback()
        flash('Fout bij verwijderen businessunit', 'error')
    return redirect(url_for('main.admin_businessunits_page'))

@main.route('/keyuser/klacht/<int:klacht_id>/toewijzen', methods=['POST'])
def keyuser_assign_klacht(klacht_id):
    role = normalized_role()
    if 'user_id' not in session or role not in ('Key user','Admin'):
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        # Haal klacht op om businessunit te checken
        klacht = services.get_klacht_by_id(klacht_id)
        if not klacht:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        if role == 'Key user':
            my_bu = session.get('businessunit_naam')
            complaint_bu = services.get_businessunit_name(klacht.businessunit_id) if klacht.businessunit_id else ''
            if my_bu and complaint_bu and complaint_bu != my_bu:
                flash('Toegang geweigerd voor deze businessunit', 'error')
                return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        nieuwe_rep = request.form.get('vertegenwoordiger_id')
        if not nieuwe_rep:
            flash('Geen gebruiker geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Check of de geselecteerde gebruiker bestaat
        new_rep = services.get_user_by_id(nieuwe_rep)
        if not new_rep:
            flash('Gekozen gebruiker niet gevonden', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Voer de update uit
        klacht.verantwoordelijke_id = int(nieuwe_rep)
        klacht.datum_laatst_bewerkt = datetime.now()
        db.session.commit()
        flash('Klacht succesvol toegewezen', 'success')

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
        bu_id = session.get('businessunit_id')
        
        # Haal klachten op via ORM
        if bu_id:
            klachten_all = db.session.query(Klacht).filter_by(businessunit_id=bu_id).all()
        else:
            klachten_all = services.get_all_klachten()
        
        # Filter open klachten
        klachten = [k for k in klachten_all if k.status != 'Afgehandeld']
        total_klachten = len(klachten)
        
        # Tel nieuwe klachten van vandaag
        today_new = len([k for k in klachten_all if is_klacht_today(k, today_str)])
    except Exception as e:
        print("Error getting keyuser stats:", e)
        traceback.print_exc()
        total_klachten = 0
        today_new = 0
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
        # Haal klacht op via ORM
        klacht = services.get_klacht_by_id(klacht_id)
        if not klacht:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        klacht_data = klacht_to_dict(klacht)
        current_role = session.get('user_rol')
        # Authorization check
        if not can_edit_klacht(klacht_data, session['user_id'], current_role):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # Capture old status BEFORE we update anything
        old_status = klacht.status

        # Haal form data op
        order_nummer = request.form.get('order_nummer', '').strip()
        artikelnummer = request.form.get('artikelnummer', '').strip()
        artikel_naam = request.form.get('artikel_naam', '').strip()
        klant_id_form = request.form.get('klant_id', '').strip()
        klant_naam_form = request.form.get('klant_naam', '').strip()
        aantal_eenheden = request.form.get('aantal_eenheden', '').strip()
        categorie_id = request.form.get('categorie_id', '').strip()
        mogelijke_oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
        klacht_omschrijving = request.form.get('reden_afwijzing', '').strip()
        businessunit = request.form.get('businessunit', '').strip() or (session.get('businessunit_naam') or '').strip()
        bu_id = services.resolve_or_create_businessunit(businessunit) if businessunit else None
        verantwoordelijke_id = request.form.get('vertegenwoordiger_id', '').strip()

        # Valideer verplichte velden
        if not categorie_id or not order_nummer or not artikelnummer or not aantal_eenheden or not klacht_omschrijving:
            flash('Categorie, ordernummer, artikelnummer, aantal eenheden en klacht omschrijving zijn verplicht', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Controleer of categorie_id bestaat
        categorie_check = services.get_categorie_by_id(categorie_id)
        if not categorie_check:
            flash('Ongeldige categorie geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Valideer dat order en product bestaan (strikte controle: geen automatische creatie)
        order_obj = services.get_order_by_nummer(order_nummer)
        product_obj = services.get_product_by_artikelnummer(artikelnummer)
        if not order_obj:
            flash('Ordernummer niet gevonden. Kies een bestaand ordernummer uit de lijst.', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))
        if not product_obj:
            flash('Artikelnummer niet gevonden. Kies een bestaand artikelnummer uit de lijst.', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Controleer consistentie tussen geselecteerde klant (form) en klant van het order
        try:
            order_klant_id = getattr(order_obj, 'klant_id', None)
            # Als gebruiker expliciet een klant meestuurt in het formulier, mag deze alleen geaccepteerd worden
            # wanneer die overeenkomt met de klant van het geselecteerde order.
            if klant_id_form:
                if order_klant_id is not None and str(order_klant_id) != str(klant_id_form):
                    flash('Geselecteerde klant komt niet overeen met klant van het ordernummer. Kies een klant die bij het order hoort.', 'error')
                    return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

            # Ongeacht of de client klant_id meestuurt: als het order hoort bij een andere klant dan
            # de klacht momenteel heeft, update de klacht en toon een info-melding (dit gebeurt bij opslaan).
            if order_klant_id is not None and str(order_klant_id) != str(klacht.klant_id):
                klacht.klant_id = int(order_klant_id)
                flash('Klant aangepast naar klant behorend bij het geselecteerde order.', 'info')
        except Exception as e:
            print(f"Warning: kon klant niet controleren/automatisch bijwerken op basis van order: {e}")

        # Haal bestaande bijlages
        existing_bijlages_raw = klacht.bijlages
        klant_id_existing = klacht.klant_id

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
                    try:
                        uploaded = upload_file_to_storage(
                            nf,
                            store_in_db=False,
                            klacht_id=klacht_id,
                            klant_naam=klacht.klant.klantnaam if klacht.klant else None,
                            klant_id_val=klant_id_existing,
                            businessunit_name=businessunit
                        )
                        if uploaded:
                            existing_bijlages.append(uploaded)
                    except Exception as e:
                        error_msg = f"Fout bij uploaden van bestand '{nf.filename}': {str(e)}"
                        print(f"ERROR - {error_msg}")
                        flash(error_msg, 'error')
                        # Stop de operatie als upload faalt
                        raise Exception(f"Upload van bijlage mislukt: {str(e)}")

        # Ensure referenced artikel/order rows exist
        # REMOVED: no longer automatically creates missing products/orders
        # Only use the artikel/order if they already exist (validated above)

        # Serialize bijlages
        serialized_bijlages = serialize_bijlages_for_db(existing_bijlages if existing_bijlages else None)
        
        # Update klacht via ORM
        klacht.order_nummer = order_nummer or None
        klacht.artikelnummer = safe_int(artikelnummer) if artikelnummer else None
        klacht.aantal_eenheden = safe_int(aantal_eenheden) if aantal_eenheden else None
        klacht.categorie_id = int(categorie_id)
        klacht.mogelijke_oorzaak = mogelijke_oorzaak or None
        klacht.klacht_omschrijving = klacht_omschrijving or None
        klacht.opmerking_status_wijziging = request.form.get('opmerking') or None
        klacht.businessunit_id = bu_id if bu_id is not None else klacht.businessunit_id
        klacht.datum_laatst_bewerkt = datetime.now()
        klacht.bijlages = serialized_bijlages

        # Alleen admin/key user kan verantwoordelijke wijzigen
        if session.get('user_rol') in ('Admin', 'Key user') and verantwoordelijke_id:
            try:
                klacht.verantwoordelijke_id = int(verantwoordelijke_id)
            except Exception:
                pass

        # Process status and prioriteit if the user is a manager
        status_in_form = request.form.get('status')
        prioriteit_in_form = request.form.get('prioriteit')

        if is_manager_role():
            if status_in_form:
                klacht.status = status_in_form
            klacht.prioriteit = True if prioriteit_in_form else False

        db.session.commit()

        # If the status changed and the user is a manager, insert history
        if is_manager_role() and status_in_form and status_in_form != old_status:
            try:
                services.create_statushistoriek(
                    klacht_id=klacht_id,
                    oude_status=old_status,
                    nieuwe_status=status_in_form,
                    gewijzigd_door=safe_int(session['user_id']),
                    opmerking=request.form.get('status_opmerking') or None
                )
            except Exception as e:
                print(f"Error inserting statushistoriek: {e}")

        flash('Klacht succesvol bijgewerkt!', 'success')

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
        # Haal klacht op via ORM
        klacht = services.get_klacht_by_id(klacht_id)
        if not klacht:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        klacht_data = klacht_to_dict(klacht)
        role = normalized_role()
        # Owner, admin or key user can delete
        if not (role in ('Admin', 'Key user') or klacht.verantwoordelijke_id == safe_int(session['user_id'])):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # Verwijder bijlages uit storage
        for bijlage in normalize_bijlages(klacht.bijlages):
            url = bijlage.get('url')
            if url:
                try:
                    delete_file_from_storage(url)
                except Exception as e:
                    print(f"Warning: error deleting attachment from storage: {e}")

        # Verwijder klacht
        db.session.delete(klacht)
        db.session.commit()
        flash('Klacht verwijderd', 'success')
    except Exception as e:
        print(f"Error deleting complaint: {e}")
        db.session.rollback()
        flash('Er ging iets mis bij verwijderen', 'error')

    return redirect(url_for('main.user_klachten'))

@main.route('/user/klachten/export', methods=['GET'])
def klachten_export():
    if 'user_id' not in session or not is_manager_role():
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.user_klachten'))

    try:
        # Haal alle klachten op via ORM
        klachten_raw = services.get_all_klachten()
        klachten = [klacht_to_dict(k) for k in klachten_raw]

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

        # Preload klant en categorie mappings
        klanten_map = {}
        try:
            klanten_all = services.get_all_klanten()
            for k in klanten_all:
                klanten_map[k.klant_id] = {
                    'klantnaam': k.klantnaam or '',
                    'ondernemingsnummer': k.ondernemingsnummer or ''
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

        # Sorteer klachten op klacht_id (oplopend) voor export
        try:
            klachten = sorted(klachten, key=lambda k: (k.get('klacht_id') or 0))
        except Exception as e_sort:
            print(f"Warning export: could not sort by klacht_id: {e_sort}")

        # Build Excel workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "Klachten"
        # Let op: bijlages/foto's worden niet meer meegenomen in de export
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
        ]
        ws.append(header)

        # set column widths for readability (aantal kolommen moet overeenkomen met header)
        widths = [12, 18, 24, 12, 24, 16, 16, 14, 12, 18, 16, 32, 32, 12, 16, 16, 18]
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
                    k.get('businessunit') or services.get_businessunit_name(k.get('businessunit_id')) or '',
                    ondernemingsnummer or k.get('ondernemingsnummer') or '',
                ]
                ws.append(row)

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
