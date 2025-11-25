from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from supabase import create_client

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
