"""Probeer Session Pooler connection strings te testen."""
import sys
from app import create_app

# Project referentie uit de huidige connection string
project_ref = "kilpcevxhcwysfllheen"
password = "GROUP10*PLACABOIS"

# Mogelijke Session Pooler formats
# Format 1: Session mode (poort 5432)
# Format 2: Transaction mode (poort 6543)

# Mogelijke regio's (meest voorkomend)
regions = ["eu-central-1", "us-east-1", "us-west-1", "ap-southeast-1"]

print("=" * 70)
print("SESSION POOLER CONNECTION STRING TESTER")
print("=" * 70)
print("\nProberen verschillende Session Pooler formats...\n")

tested_uris = []

# Test Session mode (poort 5432)
for region in regions:
    uri = f"postgresql://postgres.{project_ref}:{password}@aws-0-{region}.pooler.supabase.com:5432/postgres"
    tested_uris.append(("Session mode", region, uri))

# Test Transaction mode (poort 6543)  
for region in regions:
    uri = f"postgresql://postgres.{project_ref}:{password}@aws-0-{region}.pooler.supabase.com:6543/postgres"
    tested_uris.append(("Transaction mode", region, uri))

working_uri = None

for mode, region, uri in tested_uris:
    print(f"Testen: {mode} - {region}")
    print(f"  URI: postgresql://postgres.{project_ref}:***@aws-0-{region}.pooler.supabase.com:...")
    
    try:
        app = create_app()
        app.config['SQLALCHEMY_DATABASE_URI'] = uri
        
        with app.app_context():
            from app.models import db
            result = db.session.execute(db.text("SELECT 1 as test"))
            test_value = result.fetchone()[0]
            if test_value == 1:
                print(f"  [OK] Werkt! Regio: {region}, Mode: {mode}")
                working_uri = uri
                break
    except Exception as e:
        error_msg = str(e)
        if "could not translate" in error_msg.lower() or "name or service not known" in error_msg.lower():
            print(f"  [SKIP] Hostname niet gevonden voor deze regio")
        elif "authentication" in error_msg.lower() or "password" in error_msg.lower():
            print(f"  [SKIP] Authenticatie fout (mogelijk verkeerde regio)")
        else:
            print(f"  [FAIL] {error_msg[:60]}...")
    
    print()

if working_uri:
    print("=" * 70)
    print("WERKENDE CONNECTION STRING GEVONDEN!")
    print("=" * 70)
    print(f"\n{working_uri}\n")
    
    # Update config
    config_path = 'app/config.py'
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'SQLALCHEMY_DATABASE_URI' in line and '=' in line:
                indent = len(line) - len(line.lstrip())
                new_line = ' ' * indent + f"SQLALCHEMY_DATABASE_URI = '{working_uri}'"
                lines[i] = new_line
                break
        
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"[OK] Configuratie bijgewerkt in {config_path}")
        print("\nJe kunt nu de applicatie starten met: python run.py")
        
    except Exception as e:
        print(f"[ERROR] Kon configuratie niet updaten: {e}")
else:
    print("=" * 70)
    print("GEEN WERKENDE CONNECTION STRING GEVONDEN")
    print("=" * 70)
    print("\nMogelijke oorzaken:")
    print("1. De regio is niet in de lijst van geteste regio's")
    print("2. Je moet de Session Pooler connection string handmatig uit Supabase dashboard halen")
    print("\nINSTRUCTIES:")
    print("1. Ga naar je Supabase dashboard")
    print("2. Klik op 'Pooler settings' of verander 'Method' naar 'Session mode'")
    print("3. Kopieer de connection string die wordt getoond")
    print("4. Update handmatig app/config.py met die connection string")
    print("\nOf gebruik het script:")
    print("  python fix_database_ipv4.py 'jouw_session_pooler_connection_string'")

print("\n" + "=" * 70)

