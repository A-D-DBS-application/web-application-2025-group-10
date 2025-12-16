"""Test script om database connectie en gebruikers te controleren."""
import sys
from app import create_app
from app.models import db, Gebruiker, Businessunit

print("=" * 60)
print("DATABASE CONNECTIE TEST")
print("=" * 60)

app = create_app()

with app.app_context():
    try:
        print("\n1. Testen database connectie...")
        print(f"   Database URI: {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[1] if '@' in app.config['SQLALCHEMY_DATABASE_URI'] else 'hidden'}")
        
        # Test connectie met een simpele query
        result = db.session.execute(db.text("SELECT 1 as test"))
        test_value = result.fetchone()[0]
        if test_value == 1:
            print("   [OK] Database connectie succesvol!")
        else:
            print("   [WARNING] Connectie werkt, maar query resultaat is onverwacht")
        
    except Exception as e:
        error_msg = str(e)
        print(f"   [ERROR] Database connectie mislukt!")
        print(f"   Foutmelding: {error_msg}")
        
        if "could not translate host name" in error_msg.lower():
            print("\n   Probleem: Hostname kan niet worden opgelost")
            print("   Oplossingen:")
            print("   1. Controleer je internet verbinding")
            print("   2. Controleer of de Supabase database nog actief is")
            print("   3. Controleer of de hostname correct is in config.py")
        elif "connection refused" in error_msg.lower() or "timeout" in error_msg.lower():
            print("\n   Probleem: Kan niet verbinden met database server")
            print("   Oplossingen:")
            print("   1. Controleer of poort 5432 niet geblokkeerd is door firewall")
            print("   2. Controleer of de database server online is")
            print("   3. Controleer of je IP adres toegang heeft tot Supabase")
        elif "authentication failed" in error_msg.lower() or "password" in error_msg.lower():
            print("\n   Probleem: Authenticatie mislukt")
            print("   Oplossingen:")
            print("   1. Controleer database gebruikersnaam en wachtwoord")
            print("   2. Controleer of de credentials in config.py correct zijn")
        else:
            print("\n   Mogelijke oorzaken:")
            print("   - Geen internet verbinding")
            print("   - Database hostname niet bereikbaar")
            print("   - Verkeerde database credentials")
            print("   - Database server is down")
            print("   - Firewall blokkeert connectie")
        
        print("\n   Probeer de database connectie handmatig te testen met:")
        print("   psql 'postgresql://postgres:GROUP10*PLACABOIS@db.kilpcevxhcwysfllheen.supabase.co:5432/postgres'")
        
        # Stop niet meteen, probeer verder te gaan om andere info te tonen
        print("\n   [CONTINUE] Ga verder met andere tests...")
    
    try:
        print("\n2. Controleren tabellen...")
        # Test of tabellen bestaan
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"   [OK] Gevonden tabellen: {len(tables)}")
        if tables:
            print(f"   Tabellen: {', '.join(tables[:5])}{'...' if len(tables) > 5 else ''}")
        
    except Exception as e:
        print(f"   [WARNING] Kon tabellen niet ophalen: {e}")
    
    try:
        print("\n3. Controleren gebruikers in database...")
        user_count = db.session.query(Gebruiker).count()
        print(f"   [OK] Aantal gebruikers: {user_count}")
        
        if user_count > 0:
            print("\n   Eerste 5 gebruikers:")
            users = db.session.query(Gebruiker).limit(5).all()
            for user in users:
                print(f"   - ID: {user.gebruiker_id}, Email: {user.email}, Naam: {user.naam}, Rol: {user.rol}")
        else:
            print("   [WARNING] Geen gebruikers gevonden in database!")
            print("   Je moet eerst gebruikers aanmaken via admin panel of database.")
        
    except Exception as e:
        print(f"   [ERROR] Kon gebruikers niet ophalen: {e}")
        import traceback
        traceback.print_exc()
    
    try:
        print("\n4. Controleren businessunits...")
        bu_count = db.session.query(Businessunit).count()
        print(f"   [OK] Aantal businessunits: {bu_count}")
        
        if bu_count > 0:
            print("\n   Businessunits:")
            bus = db.session.query(Businessunit).limit(5).all()
            for bu in bus:
                print(f"   - ID: {bu.businessunit_id}, Naam: {bu.naam}")
        
    except Exception as e:
        print(f"   [WARNING] Kon businessunits niet ophalen: {e}")
    
    print("\n" + "=" * 60)
    print("TEST VOLTOOID")
    print("=" * 60)

