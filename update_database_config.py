"""Script om database configuratie te updaten."""
import sys
import os

def update_database_uri(new_uri):
    """Update de database URI in config.py"""
    config_path = 'app/config.py'
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Zoek de huidige URI regel
        lines = content.split('\n')
        updated = False
        
        for i, line in enumerate(lines):
            if 'SQLALCHEMY_DATABASE_URI' in line and '=' in line:
                # Extract de oude URI
                old_line = line
                # Maak nieuwe regel
                indent = len(line) - len(line.lstrip())
                new_line = ' ' * indent + f"SQLALCHEMY_DATABASE_URI = '{new_uri}'"
                lines[i] = new_line
                updated = True
                print(f"Oude regel: {old_line.strip()}")
                print(f"Nieuwe regel: {new_line.strip()}")
                break
        
        if updated:
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            print(f"\n[OK] Configuratie bijgewerkt in {config_path}")
            return True
        else:
            print("[ERROR] Kon SQLALCHEMY_DATABASE_URI niet vinden in config.py")
            return False
            
    except Exception as e:
        print(f"[ERROR] Kon configuratie niet updaten: {e}")
        return False

def test_connection(uri=None):
    """Test de database connectie"""
    from app import create_app
    app = create_app()
    
    if uri:
        # Tijdelijk de URI aanpassen voor test
        app.config['SQLALCHEMY_DATABASE_URI'] = uri
    
    with app.app_context():
        try:
            from app.models import db
            result = db.session.execute(db.text("SELECT 1 as test"))
            test_value = result.fetchone()[0]
            if test_value == 1:
                print("[OK] Database connectie succesvol!")
                return True
        except Exception as e:
            print(f"[ERROR] Database connectie mislukt: {e}")
            return False

if __name__ == '__main__':
    print("=" * 70)
    print("DATABASE CONFIGURATIE UPDATER")
    print("=" * 70)
    
    if len(sys.argv) > 1:
        new_uri = sys.argv[1]
        print(f"\nNieuwe database URI: {new_uri.split('@')[1] if '@' in new_uri else 'hidden'}")
        
        if update_database_uri(new_uri):
            print("\nTesten nieuwe connectie...")
            test_connection()
    else:
        print("\nGebruik: python update_database_config.py 'postgresql://user:pass@host:port/db'")
        print("\nVoorbeeld:")
        print("  python update_database_config.py 'postgresql://postgres:password@localhost:5432/klachten_db'")
        print("\nOf gebruik de interactieve checker:")
        print("  python check_database_config.py")

