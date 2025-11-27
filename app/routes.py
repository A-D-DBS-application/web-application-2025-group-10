from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from supabase import create_client
from datetime import datetime, date

main = Blueprint('main', __name__)

# Supabase configuratie
supabase_url = "https://kilpcevxhcwysfllheen.supabase.co"
supabase_key = "sb_secret_Ft6fDkZhNVImBd_cgxFWZg_lCXrcbUa"
supabase = create_client(supabase_url, supabase_key)

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
                
                # Eerst proberen met password hashing
                if stored_password and check_password_hash(stored_password, password):
                    # Login succesvol
                    session['user_id'] = user_data['gebruiker_id']
                    session['user_email'] = user_data['email']
                    session['user_naam'] = user_data['naam']
                    session['user_rol'] = user_data['rol']
                    
                    # Redirect naar dashboard voor Users, anders naar welkom pagina
                    if session['user_rol'] == 'User':
                        return redirect(url_for('main.user_dashboard'))
                    else:
                        user_info = {
                            'naam': session['user_naam'],
                            'email': session['user_email'],
                            'rol': session['user_rol']
                        }
                        flash('Login succesvol!', 'success')
                        return render_template('welkom.html', user=user_info)
                # Als plain text (voor testing)
                elif stored_password == password:
                    session['user_id'] = user_data['gebruiker_id']
                    session['user_email'] = user_data['email']
                    session['user_naam'] = user_data['naam']
                    session['user_rol'] = user_data['rol']
                    
                    # Redirect naar dashboard voor Users, anders naar welkom pagina
                    if session['user_rol'] == 'User':
                        return redirect(url_for('main.user_dashboard'))
                    else:
                        user_info = {
                            'naam': session['user_naam'],
                            'email': session['user_email'],
                            'rol': session['user_rol']
                        }
                        flash('Login succesvol!', 'success')
                        return render_template('welkom.html', user=user_info)
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
    if 'user_id' not in session or session.get('user_rol') != 'User':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    
    return render_template('user_dashboard.html')

@main.route('/user/klachten')
def user_klachten():
    if 'user_id' not in session or session.get('user_rol') != 'User':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # Haal klachten op die door deze user zijn aangemaakt
        response = supabase.table("klacht").select("*").eq("vertegenwoordiger_id", session['user_id']).execute()
        klachten = response.data if response.data else []
        
        return render_template('user_klachten.html', klachten=klachten)
    except Exception as e:
        flash('Er ging iets mis bij het ophalen van klachten', 'error')
        print(f"Error: {e}")
        return render_template('user_klachten.html', klachten=[])

@main.route('/user/klacht/<int:klacht_id>/verwijderen', methods=['POST'])
def klacht_verwijderen(klacht_id):
    if 'user_id' not in session or session.get('user_rol') != 'User':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # 1. Eerst: Zoek de klacht en controleer of het van de huidige user is
        klacht_response = supabase.table("klacht").select("vertegenwoordiger_id").eq("klacht_id", klacht_id).execute()
        
        if not klacht_response.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        klacht_data = klacht_response.data[0]
        
        # Controleer of de klacht van de huidige user is
        if klacht_data['vertegenwoordiger_id'] != session['user_id']:
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))
        
        # 2. Verwijder de KLACHT
        delete_klacht_response = supabase.table("klacht").delete().eq("klacht_id", klacht_id).execute()
        
        if delete_klacht_response.data:
            flash('Klacht succesvol verwijderd!', 'success')
        else:
            flash('Er ging iets mis bij het verwijderen van de klacht', 'error')
            
    except Exception as e:
        print(f"Verwijder error: {e}")
        flash(f'Er ging iets mis bij het verwijderen: {str(e)}', 'error')
    
    return redirect(url_for('main.user_klachten'))

@main.route('/user/klacht/<int:klacht_id>/details')
def klacht_details(klacht_id):
    if 'user_id' not in session or session.get('user_rol') != 'User':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # Controleer of de klacht van de huidige user is
        klacht_response = supabase.table("klacht").select("*, klant:klant_id(klantnaam), categorie:probleemcategorie(type)").eq("klacht_id", klacht_id).execute()
        
        if not klacht_response.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        klacht_data = klacht_response.data[0]
        
        if klacht_data['vertegenwoordiger_id'] != session['user_id']:
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # Haal categorieën op voor dropdown
        categorieen_response = supabase.table("probleemcategorie").select("categorie_id, type").execute()
        categorieen = categorieen_response.data if categorieen_response.data else []
        
        return render_template('klacht_details.html', 
                             klacht=klacht_data,
                             klacht_id=klacht_id,
                             categorieen=categorieen)
        
    except Exception as e:
        flash('Er ging iets mis bij het ophalen van de klacht details', 'error')
        print(f"Error: {e}")
        return redirect(url_for('main.user_klachten'))

@main.route('/user/klacht/aanmaken', methods=['GET', 'POST'])
def klacht_aanmaken():
    if 'user_id' not in session or session.get('user_rol') != 'User':
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
            
            print(f"DEBUG - Form data ontvangen:")
            print(f"  Klant ID: {klant_id}")
            print(f"  Categorie ID: {categorie_id}")
            print(f"  Ordernummer: {order_nummer}")
            
            # Valideer verplichte velden
            if not klant_id or not categorie_id or not order_nummer:
                flash('Klant, categorie en ordernummer zijn verplicht', 'error')
                return render_template('klacht_aanmaken.html', 
                                     user_naam=session.get('user_naam'),
                                     klanten=klanten,
                                     categorieen=categorieen)
            
            # Bereid bijlagen voor
            bijlages = {}
            if 'bijlage' in request.files:
                file = request.files['bijlage']
                if file and file.filename != '' and file.filename != 'undefined':
                    bijlages = {
                        'filename': file.filename,
                        'content_type': file.content_type or 'application/octet-stream',
                        'upload_date': datetime.utcnow().isoformat(),
                        'has_file': True
                    }
                    print(f"DEBUG - Bestand geüpload: {file.filename}")
            
            # Alleen datum (zonder uur)
            vandaag = date.today().isoformat()
            
            # Klacht aanmaken ZONDER status_platen
            nieuwe_klacht = {
                'vertegenwoordiger_id': session['user_id'],
                'klant_id': int(klant_id),
                'categorie_id': int(categorie_id),
                'order_nummer': order_nummer,  # Ordernummer direct in klacht opslaan
                'mogelijke_oorzaak': mogelijke_oorzaak or None,
                'bijlages': bijlages,
                'prioriteit': False,
                'status': 'Ingediend',
                'datum_melding': vandaag,
                'reden_afwijzing': reden_afwijzing or None,
                'gm_opmerking': None,
                'datum_laatst_bewerkt': vandaag
            }
            
            response = supabase.table("klacht").insert(nieuwe_klacht).execute()
            
            if response.data:
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
    
    return render_template('klacht_aanmaken.html', 
                         user_naam=session.get('user_naam'),
                         klanten=klanten,
                         categorieen=categorieen)

@main.route('/user/klacht/<int:klacht_id>/bewerken', methods=['POST'])
def klacht_bewerken(klacht_id):
    if 'user_id' not in session or session.get('user_rol') != 'User':
        flash('Toegang geweigerd', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # Controleer of de klacht van de huidige user is
        klacht_check = supabase.table("klacht").select("vertegenwoordiger_id").eq("klacht_id", klacht_id).execute()
        
        if not klacht_check.data:
            flash('Klacht niet gevonden', 'error')
            return redirect(url_for('main.user_klachten'))
        
        if klacht_check.data[0]['vertegenwoordiger_id'] != session['user_id']:
            flash('Toegang geweigerd', 'error')
            return redirect(url_for('main.user_klachten'))

        # Haal form data op
        order_nummer = request.form.get('order_nummer', '').strip()
        categorie_id = request.form.get('categorie_id', '').strip()
        mogelijke_oorzaak = request.form.get('mogelijke_oorzaak', '').strip()
        reden_afwijzing = request.form.get('reden_afwijzing', '').strip()
        # status_platen is verwijderd

        # Valideer categorie_id
        if not categorie_id:
            flash('Categorie is verplicht', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Controleer of categorie_id bestaat
        categorie_check = supabase.table("probleemcategorie").select("categorie_id").eq("categorie_id", int(categorie_id)).execute()
        if not categorie_check.data:
            flash('Ongeldige categorie geselecteerd', 'error')
            return redirect(url_for('main.klacht_details', klacht_id=klacht_id))

        # Update de klacht (ZONDER status_platen)
        update_data = {
            'order_nummer': order_nummer or None,
            'categorie_id': int(categorie_id),
            'mogelijke_oorzaak': mogelijke_oorzaak or None,
            'reden_afwijzing': reden_afwijzing or None,
            'datum_laatst_bewerkt': datetime.utcnow().isoformat()
        }

        response = supabase.table("klacht").update(update_data).eq("klacht_id", klacht_id).execute()

        if response.data:
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
        return redirect(url_for('main.klacht_details', klacht_id=klacht_id))