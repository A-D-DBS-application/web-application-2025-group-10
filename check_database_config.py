"""Script om database configuratie te controleren en te helpen bijwerken."""
import sys
import os

print("=" * 70)
print("DATABASE CONFIGURATIE CHECKER")
print("=" * 70)

# Huidige configuratie
current_uri = 'postgresql://postgres:GROUP10*PLACABOIS@db.kilpcevxhcwysfllheen.supabase.co:5432/postgres'

print("\nHUIDIGE CONFIGURATIE:")
print(f"Database URI: {current_uri}")
print(f"Hostname: db.kilpcevxhcwysfllheen.supabase.co")
print(f"Port: 5432")
print(f"Database: postgres")
print(f"User: postgres")

print("\n" + "=" * 70)
print("INSTRUCTIES VOOR SUPABASE")
print("=" * 70)
print("""
1. Ga naar https://supabase.com en log in
2. Selecteer je project (of maak een nieuw project aan)
3. Ga naar: Project Settings > Database
4. Zoek naar "Connection string" of "Connection pooling"
5. Kopieer de connection string

MOGELIJKE CONNECTION STRINGS:
- Direct connection: postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres
- Connection pooler: postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres
- Session mode: postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres

LET OP:
- Vervang [PASSWORD] met je database wachtwoord
- Vervang [PROJECT-REF] met je project referentie
- Vervang [REGION] met je regio (bijv. eu-central-1)
""")

print("\n" + "=" * 70)
print("ALTERNATIEVE OPLOSSINGEN")
print("=" * 70)
print("""
Als je Supabase database niet meer werkt, kun je:

1. LOKALE DATABASE (voor development):
   - Installeer PostgreSQL lokaal
   - Gebruik: postgresql://postgres:password@localhost:5432/klachten_db
   - Importeer de database dump uit "Database dumb/databasedump.sql"

2. NIEUWE SUPABASE DATABASE:
   - Maak een nieuw Supabase project aan
   - Gebruik de nieuwe connection string
   - Importeer de database dump

3. ANDERE CLOUD DATABASE:
   - Heroku Postgres
   - AWS RDS
   - Google Cloud SQL
   - Azure Database
""")

print("\n" + "=" * 70)
print("WIL JE DE CONFIGURATIE UPDATEN?")
print("=" * 70)
response = input("\nVoer nieuwe database URI in (of druk Enter om over te slaan): ").strip()

if response:
    # Update config.py
    config_path = 'app/config.py'
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Vervang de database URI
        old_uri = current_uri
        new_content = content.replace(old_uri, response)
        
        if new_content != content:
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"\n[OK] Configuratie bijgewerkt in {config_path}")
            print(f"Nieuwe URI: {response.split('@')[1] if '@' in response else 'hidden'}")
            
            # Test de nieuwe connectie
            print("\nTesten nieuwe connectie...")
            from app import create_app
            app = create_app()
            with app.app_context():
                try:
                    from app.models import db
                    db.session.execute(db.text("SELECT 1"))
                    print("[OK] Nieuwe database connectie werkt!")
                except Exception as e:
                    print(f"[ERROR] Nieuwe connectie werkt niet: {e}")
        else:
            print("[WARNING] Geen wijzigingen gemaakt")
    except Exception as e:
        print(f"[ERROR] Kon configuratie niet updaten: {e}")
else:
    print("\nGeen wijzigingen gemaakt. Je kunt later handmatig app/config.py aanpassen.")

print("\n" + "=" * 70)

