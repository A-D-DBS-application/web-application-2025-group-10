"""Script om database configuratie te updaten naar Session Pooler voor IPv4 compatibiliteit."""
import sys

print("=" * 70)
print("DATABASE CONFIGURATIE FIX - IPv4 COMPATIBILITEIT")
print("=" * 70)

print("""
Het probleem: Je Supabase database direct connection is niet IPv4 compatible.
De oplossing: Gebruik de Session Pooler connection string.

INSTRUCTIES:
1. In je Supabase dashboard, ga naar de "Connect to your project" modal
2. Klik op de "Method" dropdown en selecteer "Session mode" of "Connection pooling"
3. Kopieer de connection string die begint met:
   postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres
   OF
   postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres

4. Vervang [YOUR-PASSWORD] met je database wachtwoord (GROUP10*PLACABOIS)
""")

# Voorbeeld Session Pooler format
example_pooler = "postgresql://postgres.kilpcevxhcwysfllheen:GROUP10*PLACABOIS@aws-0-eu-central-1.pooler.supabase.com:5432/postgres"

print(f"\nVOORBEELD FORMAT:")
print(f"{example_pooler}")

print("\n" + "=" * 70)
print("WIL JE DE CONFIGURATIE UPDATEN?")
print("=" * 70)

if len(sys.argv) > 1:
    new_uri = sys.argv[1]
    print(f"\nNieuwe connection string ontvangen.")
    print(f"Host: {new_uri.split('@')[1].split('/')[0] if '@' in new_uri else 'hidden'}")
    
    # Update config.py
    config_path = 'app/config.py'
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        updated = False
        
        for i, line in enumerate(lines):
            if 'SQLALCHEMY_DATABASE_URI' in line and '=' in line:
                indent = len(line) - len(line.lstrip())
                new_line = ' ' * indent + f"SQLALCHEMY_DATABASE_URI = '{new_uri}'"
                lines[i] = new_line
                updated = True
                print(f"\nOude regel: {line.strip()}")
                print(f"Nieuwe regel: {new_line.strip()}")
                break
        
        if updated:
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            print(f"\n[OK] Configuratie bijgewerkt in {config_path}")
            
            # Test de nieuwe connectie
            print("\nTesten nieuwe connectie...")
            from app import create_app
            app = create_app()
            with app.app_context():
                try:
                    from app.models import db
                    result = db.session.execute(db.text("SELECT 1 as test"))
                    test_value = result.fetchone()[0]
                    if test_value == 1:
                        print("[OK] Database connectie succesvol!")
                        print("\nJe kunt nu de applicatie starten met: python run.py")
                    else:
                        print("[WARNING] Connectie werkt, maar query resultaat is onverwacht")
                except Exception as e:
                    print(f"[ERROR] Connectie test mislukt: {e}")
                    print("\nControleer:")
                    print("1. Of je de Session Pooler connection string hebt gebruikt")
                    print("2. Of je wachtwoord correct is")
                    print("3. Of je internet verbinding werkt")
        else:
            print("[ERROR] Kon SQLALCHEMY_DATABASE_URI niet vinden in config.py")
    except Exception as e:
        print(f"[ERROR] Kon configuratie niet updaten: {e}")
else:
    print("\nGebruik dit script met je Session Pooler connection string:")
    print("  python fix_database_ipv4.py 'postgresql://postgres.xxx:password@aws-0-xxx.pooler.supabase.com:5432/postgres'")
    print("\nOf pas handmatig app/config.py aan met de Session Pooler connection string.")

print("\n" + "=" * 70)

