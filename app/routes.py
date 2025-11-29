from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response, make_response
import csv
import io
import os
import smtplib
from email.message import EmailMessage

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename       # <--- NIEUW
from supabase import create_client
from datetime import datetime, date
import uuid                                      # <--- NIEUW
import traceback                                 # <--- NIEUW for better debugging
import base64  # <--- NIEUW
import json  # <--- NIEUW: for parsing bijlages

main = Blueprint('main', __name__)

# Supabase configuratie
supabase_url = "https://kilpcevxhcwysfllheen.supabase.co"
supabase_key = "sb_secret_Ft6fDkZhNVImBd_cgxFWZg_lCXrcbUa"
supabase = create_client(supabase_url, supabase_key)

# NIEUW: naam van je Storage bucket
BUCKET_NAME = "bijlages"

# Toggle: bestanden in DB opslaan i.p.v. Storage (let op: base64 in DB kan groot worden)
STORE_FILES_IN_DB = True  # set to False to keep using Supabase Storage and store public URLs


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
					session['user_id'] = user_data['gebruiker_id']
					session['user_email'] = user_data['email']
					session['user_naam'] = user_data['naam']
					# Normalize role display: Capitalise only first character (e.g., "Key user")
					session['user_rol'] = (user_data.get('rol') or '').strip().capitalize()

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
					session['user_id'] = user_data['gebruiker_id']
					session['user_email'] = user_data['email']
					session['user_naam'] = user_data['naam']
					session['user_rol'] = (user_data.get('rol') or '').strip().capitalize()

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

@main.route('/user/klachten')
def user_klachten():
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))

    role = normalized_role()
    try:
        # Try to select with relational joins so fewer server calls are required
        try:
            query = supabase.table("klacht").select("*, klant:klant_id(klantnaam), categorie:probleemcategorie(type)").order("datum_melding", {"ascending": False})
            # if User: only their own klachten
            if role == 'User':
                user_id_int = safe_int(session['user_id'])
                query = query.eq("vertegenwoordiger_id", user_id_int)
            response = query.execute()
            check_supabase_response(response, "fetching klachten")
            klachten = response.data if response.data else []
        except Exception as e:
            # Fallback: simpler select; if something went wrong with joins we still get data
            print(f"Warning: join select failed, falling back. Reason: {e}")
            query = supabase.table("klacht").select("*")
            if role == 'User':
                user_id_int = safe_int(session['user_id'])
                query = query.eq("vertegenwoordiger_id", user_id_int)
            response = query.execute()
            check_supabase_response(response, "fetching klachten fallback")
            klachten = response.data if response.data else []

        # Apply filters from GET params
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

        # categorieen for filter options (simple select)
        categorieen_resp = supabase.table("probleemcategorie").select("categorie_id, type").execute()
        check_supabase_response(categorieen_resp, "fetching probleemcategorie")
        categorieen = categorieen_resp.data if categorieen_resp.data else []

        klanten_resp = supabase.table("klant").select("klant_id, klantnaam").execute()
        check_supabase_response(klanten_resp, "fetching klanten")
        klanten = klanten_resp.data if klanten_resp.data else []

        return render_template('user_klachten.html', klachten=klachten, categorieen=categorieen, klanten=klanten)
    except Exception as e:
        print(f"Exception in user_klachten: {e}")
        traceback.print_exc()
        flash('Er ging iets mis bij het ophalen van klachten', 'error')
        # Return with empty lists so template can still render
        return render_template('user_klachten.html', klachten=[], categorieen=[], klanten=[])


@main.route('/user/klacht/<int:klacht_id>/details')
def klacht_details(klacht_id):
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))

    try:
        # use relational select to get klant + categorie with one call
        klacht_response = supabase.table("klacht").select("*, klant:klant_id(klantnaam), categorie:probleemcategorie(type)").eq("klacht_id", safe_int(klacht_id)).execute()
        check_supabase_response(klacht_response, "fetching single complaint")
        if not klacht_response.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        klacht_data = klacht_response.data[0]

        # Authorization check - ensure numbers are comparable
        if not can_view_klacht(klacht_data, safe_int(session['user_id']), session.get('user_rol')):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # statushistoriek (defensive)
        try:
            sh_resp = supabase.table("statushistoriek").select("*").eq("klacht_id", safe_int(klacht_id)).order("datum_wijziging", {"ascending": False}).execute()
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
                reps_resp = supabase.table("gebruiker").select("gebruiker_id, naam").eq("rol", "User").execute()
                check_supabase_response(reps_resp, "fetching reps")
                vertegenw = reps_resp.data if reps_resp.data else []
            except Exception as e:
                print(f"Warning: could not fetch vertegenw: {e}")
                vertegenw = []

        # Bijlages handling: safe parsing (list/dict/JSON string/data-url)
        if klacht_data.get('bijlages'):
            parsed_bijlages = []
            raw_bijlages = klacht_data.get('bijlages')
            # If bijlages is a string (e.g. JSON string), try to parse
            if isinstance(raw_bijlages, str):
                try:
                    raw_bijlages = json.loads(raw_bijlages)
                except Exception:
                    # Not JSON — leave as is and skip parsing
                    raw_bijlages = [raw_bijlages]

            if isinstance(raw_bijlages, list):
                for b in raw_bijlages:
                    b_copy = dict(b) if isinstance(b, dict) else {"url": b, "naam": str(b)}
                    if not b_copy.get('id'):
                        b_copy['id'] = str(uuid.uuid4())
                    if b_copy.get('content') and not b_copy.get('url'):
                        ct = b_copy.get('content_type', 'application/octet-stream')
                        b_copy['url'] = f"data:{ct};base64,{b_copy.get('content')}"
                    content_type = (b_copy.get('content_type') or '') or ''
                    url_lower = (b_copy.get('url') or '').lower()
                    if content_type.startswith('image/') or url_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')):
                        b_copy['is_image'] = True
                    else:
                        b_copy['is_image'] = False
                    parsed_bijlages.append(b_copy)
            else:
                # unknown format, still make sure template can handle one element list
                parsed_bijlages = [{"id": str(uuid.uuid4()), "url": str(raw_bijlages), "naam": str(raw_bijlages), "is_image": False}]

            klacht_data['bijlages'] = parsed_bijlages

        # After we fetched klacht_data in klacht_details, ensure we have the creator name even if relation wasn't joined:
        # Ensure we have the vertegenwoordiger object (fill from users if missing)
        if not klacht_data.get('vertegenwoordiger') and klacht_data.get('vertegenwoordiger_id'):
            try:
                uresp = supabase.table("gebruiker").select("naam").eq("gebruiker_id", int(klacht_data['vertegenwoordiger_id'])).execute()
                check_supabase_response(uresp, "fetch creator name for details")
                if uresp.data and len(uresp.data) > 0:
                    klacht_data['vertegenwoordiger'] = {'naam': uresp.data[0].get('naam')}
            except Exception as e:
                print(f"Warning: could not fetch creator name for klacht {klacht_id}: {e}")

        return render_template('klacht_details.html', klacht=klacht_data, klacht_id=klacht_id, categorieen=categorieen, statushistoriek=statushistoriek, vertegenw=vertegenw)
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
    
    if request.method == 'POST':
        try:
            # Haal form data op
            klant_id = request.form.get('klant_id', '').strip()
            categorie_id = request.form.get('categorie_id', '').strip()
            order_nummer = request.form.get('order_nummer', '').strip()
            mogelijke_oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
            reden_afwijzing = request.form.get('reden_afwijzing', '').strip()
            notify_customer = request.form.get('notify_customer') == 'on'
            
            print("DEBUG - Form data ontvangen:")
            print(f"  Klant ID: {klant_id}")
            print(f"  Categorie ID: {categorie_id}")
            print(f"  Ordernummer: {order_nummer}")
            
            # Valideer verplichte velden
            if not klant_id or not categorie_id or not order_nummer:
                flash('Klant, categorie en ordernummer zijn verplicht', 'error')
                return render_template(
                    'klacht_aanmaken.html',
                    user_naam=session.get('user_naam'),
                    klanten=klanten,
                    categorieen=categorieen
                )

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
            # ================== EINDE AANGESCHERPT ==================

            # Alleen datum (zonder uur)
            vandaag = date.today().isoformat()
            
            # Klacht aanmaken
            nieuwe_klacht = {
                'vertegenwoordiger_id': session['user_id'],
                'klant_id': int(klant_id),
                'categorie_id': int(categorie_id),
                'order_nummer': order_nummer,
                'mogelijke_oorzaak': mogelijke_oorzaak or None,
                'bijlages': bijlages,              # <--- hier komt de JSON in de tabel
                'prioriteit': False,
                'status': 'Ingediend',
                'datum_melding': vandaag,
                'reden_afwijzing': reden_afwijzing or None,
                'gm_opmerking': None,
                'datum_laatst_bewerkt': vandaag
            }
            
            response = supabase.table("klacht").insert(nieuwe_klacht).execute()
            
            if response.data:
                # Notify GM or Sales manager if needed
                # Simple notification: find all users with role Admin/Key user in same bedrijf
                try:
                    # send a very simple email
                    if notify_customer:
                        # Get klant details to email if present
                        klant_email = None
                        if klant_id:
                            kresp = supabase.table("klant").select("email").eq("klant_id", int(klant_id)).execute()
                            klant_email = kresp.data[0].get('email') if (kresp.data and kresp.data[0]) else None
                        if klant_email:
                            send_email("Uw klacht is aangemeld", f"Beste klant, uw klacht is aangemeld. Klacht ID: {response.data[0].get('klacht_id')}", [klant_email])
                except Exception as e:
                    print(f"Error sending notification: {e}")

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
        categorieen=categorieen
    )


@main.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    if normalized_role() != 'Admin':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.user_dashboard'))

    try:
        # Fetch representatives and all users for mapping (admins want to see all creators)
        reps_resp = supabase.table("gebruiker").select("gebruiker_id, naam, email").execute()
        check_supabase_response(reps_resp, "fetching all users")
        vertegenw = reps_resp.data if reps_resp.data else []

        # Build a quick map id -> naam for fallback usage
        rep_map = {r['gebruiker_id']: r['naam'] for r in vertegenw if r.get('gebruiker_id') is not None}

        # Try relational select for open klachten (exclude 'Afgehandeld') and order by prioriteit desc, datum_melding desc
        klachten = []
        try:
            klachten_resp = supabase.table("klacht").select(
                "*, klant:klant_id(klantnaam), categorie:probleemcategorie(type), vertegenwoordiger:vertegenwoordiger_id(naam)"
            ).neq("status", "Afgehandeld").order("prioriteit", {"ascending": False}).order("datum_melding", {"ascending": False}).execute()
            check_supabase_response(klachten_resp, "fetching open klachten for admin with relations")
            klachten = klachten_resp.data if klachten_resp.data else []
        except Exception as e:
            # Fallback: fetch all, filter and sort locally
            print(f"Warning: relational select for admin klachten failed: {e}")
            traceback.print_exc()
            fallback_resp = supabase.table("klacht").select("*").execute()
            check_supabase_response(fallback_resp, "fetching klachten fallback for admin")
            raw_klachten = fallback_resp.data if fallback_resp.data else []
            filtered = [k for k in raw_klachten if (k.get('status') or '').strip() != 'Afgehandeld']
            # Map representative name into each complaint
            for k in filtered:
                if not k.get('vertegenwoordiger'):
                    rep_id = k.get('vertegenwoordiger_id')
                    if rep_id and rep_id in rep_map:
                        k['vertegenwoordiger'] = {'naam': rep_map.get(rep_id)}
                    else:
                        k['vertegenwoordiger'] = None
            try:
                # Sort by priority then date desc
                filtered_sorted = sorted(filtered, key=lambda x: (0 if bool(x.get('prioriteit')) else 1), reverse=False)
                filtered_sorted = sorted(filtered_sorted, key=lambda x: (x.get('datum_melding') or ''), reverse=True)
                klachten = filtered_sorted
            except Exception:
                klachten = sorted(filtered, key=lambda x: (0 if bool(x.get('prioriteit')) else 1), reverse=False)

        # Ensure each result has representative object
        for k in klachten:
            if not k.get('vertegenwoordiger'):
                rep_id = k.get('vertegenwoordiger_id')
                if rep_id and rep_id in rep_map:
                    k['vertegenwoordiger'] = {'naam': rep_map.get(rep_id)}
                else:
                    k['vertegenwoordiger'] = None

        total_klachten = len(klachten)

        # Also fetch the users and counts for the admin user-management card
        gebruikers_resp = supabase.table("gebruiker").select("gebruiker_id, naam, email, rol").execute()
        check_supabase_response(gebruikers_resp, "fetching users for admin")
        gebruikers = gebruikers_resp.data if gebruikers_resp.data else []
        total_gebruikers = len(gebruikers)
    except Exception as e:
        print(f"Error admin stats: {e}")
        traceback.print_exc()
        total_klachten = 0
        total_gebruikers = 0
        gebruikers = []
        vertegenw = []
        klachten = []

    # Defensive: ensure klachten is a list
    if not isinstance(klachten, list):
        klachten = list(klachten) if klachten else []

    return render_template('admin_dashboard.html', total_klachten=total_klachten, total_gebruikers=total_gebruikers, gebruikers=gebruikers, klachten=klachten, vertegenw=vertegenw)

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

    if not naam or not email:
        flash('Naam en email zijn verplicht', 'error')
        return redirect(url_for('main.user_dashboard'))
    try:
        hashed = generate_password_hash(wachtwoord)
        user_obj = {
            'naam': naam,
            'email': email,
            'rol': (rol or '').strip().capitalize(),
            'wachtwoord': hashed
        }
        resp = supabase.table("gebruiker").insert(user_obj).execute()
        if resp.data:
            flash('Gebruiker succesvol aangemaakt', 'success')
        else:
            flash('Fout bij aanmaken gebruiker', 'error')
    except Exception as e:
        print(f"Error creating user: {e}")
        flash('Er ging iets mis bij het aanmaken van de gebruiker', 'error')
    # Redirect to appropriate dashboard based on creator's role
    if session.get('user_rol', '').upper() == 'ADMIN':
        return redirect(url_for('main.admin_dashboard'))
    elif session.get('user_rol', '').upper() == 'KEY USER':
        return redirect(url_for('main.keyuser_dashboard'))
    else:
        return redirect(url_for('main.user_dashboard'))

@main.route('/keyuser/klacht/<int:klacht_id>/toewijzen', methods=['POST'])
def keyuser_assign_klacht(klacht_id):
    role = normalized_role()
    if 'user_id' not in session or role not in ('Key user','Admin'):
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    try:
        nieuwe_rep = request.form.get('vertegenwoordiger_id')
        if not nieuwe_rep:
            flash('Geen vertegenwoordiger geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Check whether the selected user exists
        new_rep_resp = supabase.table("gebruiker").select("*").eq("gebruiker_id", int(nieuwe_rep)).execute()
        if not new_rep_resp.data:
            flash('Gekozen vertegenwoordiger niet gevonden', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))
        new_rep = new_rep_resp.data[0]

        # Ensure target has role 'User' (vertegenwoordiger)
        if new_rep.get('rol') != 'User':
            flash('Selecteer een vertegenwoordiger (User)', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # perform the update - Key user can assign across companies
        update_resp = supabase.table("klacht").update({
            'vertegenwoordiger_id': int(nieuwe_rep),
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

    try:
        # Fetch representatives (Users) -> change: fetch all users so we also know admins/key users who created klachten
        reps_resp = supabase.table("gebruiker").select("gebruiker_id, naam, email").execute()
        check_supabase_response(reps_resp, "fetching reps")
        vertegenw = reps_resp.data if reps_resp.data else []

        # Build a quick map id -> naam for fallback usage
        rep_map = {r['gebruiker_id']: r['naam'] for r in vertegenw if r.get('gebruiker_id') is not None}

        # Try relational select for open klachten (exclude 'Afgehandeld') and order by prioriteit desc, datum_melding desc
        klachten = []
        try:
            klachten_resp = supabase.table("klacht").select(
                "*, klant:klant_id(klantnaam), categorie:probleemcategorie(type), vertegenwoordiger:vertegenwoordiger_id(naam)"
            ).neq("status", "Afgehandeld").order("prioriteit", {"ascending": False}).order("datum_melding", {"ascending": False}).execute()
            check_supabase_response(klachten_resp, "fetching open klachten with relations")
            klachten = klachten_resp.data if klachten_resp.data else []
        except Exception as e:
            # If relational select fails, fallback to simpler query and sort/filter locally
            print(f"Warning: relational select for keyuser open klachten failed: {e}")
            traceback.print_exc()
            fallback_resp = supabase.table("klacht").select("*").execute()
            check_supabase_response(fallback_resp, "fetching klachten fallback")
            # Ensure data exists before filtering
            raw_klachten = fallback_resp.data if fallback_resp.data else []
            # Filter out 'Afgehandeld'
            filtered = [k for k in raw_klachten if (k.get('status') or '').strip() != 'Afgehandeld']
            # Add representative name using rep_map
            for k in filtered:
                if not k.get('vertegenwoordiger'):
                    rep_id = k.get('vertegenwoordiger_id')
                    if rep_id and rep_id in rep_map:
                        k['vertegenwoordiger'] = {'naam': rep_map.get(rep_id)}
                    else:
                        k['vertegenwoordiger'] = None
            # Sort by prioriteit (True first) then datum_melding DESC
            try:
                filtered_sorted = sorted(filtered, key=lambda x: (0 if bool(x.get('prioriteit')) else 1), reverse=False)
                filtered_sorted = sorted(filtered_sorted, key=lambda x: (x.get('datum_melding') or ''), reverse=True)
                klachten = filtered_sorted
            except Exception:
                klachten = sorted(filtered, key=lambda x: (0 if bool(x.get('prioriteit')) else 1), reverse=False)

        # Ensure each resultaat has vertegenwoordiger object (use rep_map if relation not provided)
        for k in klachten:
            if not k.get('vertegenwoordiger'):
                rep_id = k.get('vertegenwoordiger_id')
                if rep_id and rep_id in rep_map:
                    k['vertegenwoordiger'] = {'naam': rep_map.get(rep_id)}
                else:
                    k['vertegenwoordiger'] = None

        total_klachten = len(klachten)
    except Exception as e:
        print("Error getting keyuser stats:", e)
        traceback.print_exc()
        total_klachten = 0
        vertegenw = []
        klachten = []

    # Defensive: ensure klachten is a list (some Supabase clients return dict or None)
    if not isinstance(klachten, list):
        klachten = list(klachten) if klachten else []

    print(f"DEBUG: keyuser_dashboard found {len(klachten)} klachten and {len(vertegenw)} vertegenw")
    return render_template('keyuser_dashboard.html', total_klachten=total_klachten, klachten=klachten, vertegenw=vertegenw)

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
    if role_norm == 'Admin':
        return True
    if role_norm == 'Key user':
        return True
    if role_norm == 'User':
        return klacht.get('vertegenwoordiger_id') == user_id
    return False

def can_edit_klacht(klacht, user_id, user_role):
    role_norm = (user_role or '').strip().capitalize()
    if role_norm in ('Admin', 'Key user'):
        return True
    return klacht.get('vertegenwoordiger_id') == user_id

# Simple send_email helper (will fallback to print; configure env for SMTP)
def send_email(subject, body, to):
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    if not smtp_host or not smtp_user or not smtp_pass:
        print(f"[EMAIL] to={to} subject={subject} body={body}")
        return False
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = smtp_user
        msg['To'] = to if isinstance(to, str) else ', '.join(to)
        msg.set_content(body)
        with smtplib.SMTP(smtp_host, smtp_port) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@main.route('/user/klacht/<int:klacht_id>/bewerken', methods=['POST'])
def klacht_bewerken(klacht_id):
    if 'user_id' not in session:
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # Controleer of de klacht van de huidige user is
        klacht_check = supabase.table("klacht").select("vertegenwoordiger_id, status").eq("klacht_id", klacht_id).execute()
        
        if not klacht_check.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        klacht_owner_id = klacht_check.data[0]['vertegenwoordiger_id']
        current_role = session.get('user_rol')
        # authorization: check if current user can edit this complaint
        if not can_edit_klacht({'vertegenwoordiger_id': klacht_owner_id}, session['user_id'], current_role):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # Capture old status BEFORE we update anything
        try:
            old_status = klacht_check.data[0].get('status')
        except Exception:
            old_status = None

        # Haal form data op
        order_nummer = request.form.get('order_nummer', '').strip()
        categorie_id = request.form.get('categorie_id', '').strip()
        mogelijke_oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
        reden_afwijzing = request.form.get('reden_afwijzing', '').strip()
        vertegenwoordiger_id = request.form.get('vertegenwoordiger_id', '').strip()  # nieuw

        # Valideer categorie_id
        if not categorie_id:
            flash('Categorie is verplicht', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Controleer of categorie_id bestaat
        categorie_check = supabase.table("probleemcategorie").select("categorie_id").eq("categorie_id", int(categorie_id)).execute()
        if not categorie_check.data:
            flash('Ongeldige categorie geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Haal bestaande klacht met bijlages
        klacht_get_resp = supabase.table("klacht").select("bijlages").eq("klacht_id", klacht_id).execute()
        existing_bijlages = []
        if klacht_get_resp.data and len(klacht_get_resp.data) > 0:
            existing_bijlages = klacht_get_resp.data[0].get('bijlages') or []
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

        # Build update_data — include status/prioriteit BEFORE update if manager
        update_data = {
            'order_nummer': order_nummer or None,
            'categorie_id': int(categorie_id),
            'mogelijke_oorzaak': mogelijke_oorzaak or None,
            'reden_afwijzing': reden_afwijzing or None,
            'datum_laatst_bewerkt': datetime.utcnow().isoformat(),
            'bijlages': existing_bijlages if existing_bijlages else None
        }

        # Alleen admin/key user kan vertegenwoordiger wijzigen
        if session.get('user_rol') in ('Admin', 'Key user') and vertegenwoordiger_id:
            try:
                update_data['vertegenwoordiger_id'] = int(vertegenwoordiger_id)
            except Exception:
                # keep it safe — ignore invalid int casting
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
        response = supabase.table("klacht").update(update_data).eq("klacht_id", klacht_id).execute()

        if response.data:
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
                    sh_resp = supabase.table("statushistoriek").insert(hist_obj).execute()
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
            if hasattr(response, 'error') and response.error:
                error_msg += f": {response.error.message}"
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
        klacht = kresp.data[0]

        role = normalized_role()
        # owner, admin or key user can delete
        if not (role in ('Admin', 'Key user') or klacht.get('vertegenwoordiger_id') == session['user_id']):
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # attempt to delete any attachments from storage (safely)
        for bijlage in (klacht.get('bijlages') or []):
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
        if del_resp.error:
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
        # fetch all klachten (we'll filter locally for consistency with UI)
        resp = supabase.table("klacht").select("*").execute()
        check_supabase_response(resp, "export: fetching klachten")
        klachten = resp.data if resp.data else []

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

        # Build CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        header = [
            'klacht_id',
            'vertegenwoordiger_id',
            'vertegenwoordiger_naam',
            'klant_id',
            'klantnaam',
            'order_nummer',
            'categorie_id',
            'categorie_type',
            'status',
            'prioriteit',
            'datum_melding'
        ]
        writer.writerow(header)

        for k in klachten:
            try:
                klacht_id = k.get('klacht_id')
                verteg_id = k.get('vertegenwoordiger_id')
                vertegenw_naam = ''
                if isinstance(k.get('vertegenwoordiger'), dict):
                    vertegenw_naam = k.get('vertegenwoordiger').get('naam') or ''
                # if vertegenw not present, try to fetch or fallback empty
                if not vertegenw_naam and verteg_id:
                    vertegenw_naam = ''  # avoid fetching inside loop for performance

                klant_id_val = k.get('klant_id')
                klantnaam = k.get('klant', {}).get('klantnaam') if isinstance(k.get('klant'), dict) else ''
                cat_id = k.get('categorie_id')
                cat_type = k.get('categorie', {}).get('type') if isinstance(k.get('categorie'), dict) else ''
                prioriteit = k.get('prioriteit')
                # Ensure proper string values and avoid nested dicts
                row = [
                    klacht_id,
                    verteg_id,
                    vertegenw_naam,
                    klant_id_val,
                    klantnaam,
                    k.get('order_nummer') or '',
                    cat_id,
                    cat_type,
                    k.get('status') or '',
                    str(prioriteit),
                    k.get('datum_melding') or ''
                ]
                writer.writerow([str(item) for item in row])
            except Exception as e:
                print(f"Warning: failed to write row for klacht {k.get('klacht_id')}: {e}")
                # continue with rest

        csv_data = output.getvalue()
        output.close()

        # Build response with timestamped filename
        filename = f"klachten_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        response = make_response(csv_data)
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        return response

    except Exception as e:
        print(f"Exception in klachten_export: {e}")
        traceback.print_exc()
        flash('Er ging iets mis bij het exporteren van klachten', 'error')
        return redirect(url_for('main.user_klachten'))

def check_supabase_response(resp, ctx=""):
	"""Check supabase response for errors and raise if present (or return data)."""
	if resp is None:
		raise Exception(f"Empty response from Supabase at {ctx}")
	# supabase-python response has .error attribute; sometimes None, sometimes dict
	err = getattr(resp, 'error', None)
	if err:
		# try extract message if present
		msg = err.message if hasattr(err, 'message') else repr(err)
		print(f"Supabase error in {ctx}: {msg}")
		raise Exception(f"Supabase error in {ctx}: {msg}")
	return resp
