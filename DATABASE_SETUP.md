# Database Setup Instructies

## Probleem
De database connectie faalt met de fout: `could not translate host name "db.kilpcevxhcwysfllheen.supabase.co" to address`

## Oplossingen

### Optie 1: Supabase Database Controleren en Updaten

1. **Ga naar Supabase Dashboard**
   - Open https://supabase.com
   - Log in met je account
   - Selecteer je project

2. **Vind de Connection String**
   - Ga naar: **Project Settings** > **Database**
   - Scroll naar "Connection string" sectie
   - Kopieer de connection string (gebruik bij voorkeur "Connection pooling" voor betere performance)

3. **Update config.py**
   - Open `app/config.py`
   - Vervang de regel:
     ```python
     SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:GROUP10*PLACABOIS@db.kilpcevxhcwysfllheen.supabase.co:5432/postgres'
     ```
   - Met je nieuwe connection string:
     ```python
     SQLALCHEMY_DATABASE_URI = 'postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres'
     ```

4. **Test de Connectie**
   ```bash
   python test_database.py
   ```

### Optie 2: Lokale PostgreSQL Database (Development)

Als je lokaal wilt ontwikkelen zonder Supabase:

1. **Installeer PostgreSQL**
   - Download van: https://www.postgresql.org/download/
   - Installeer en maak een database aan:
     ```sql
     CREATE DATABASE klachten_db;
     ```

2. **Update config.py**
   ```python
   SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:jouw_wachtwoord@localhost:5432/klachten_db'
   ```

3. **Importeer Database Dump**
   ```bash
   psql -U postgres -d klachten_db -f "Database dumb/databasedump.sql"
   ```

### Optie 3: Nieuwe Supabase Database Aanmaken

1. **Maak Nieuw Project**
   - Ga naar https://supabase.com
   - Klik "New Project"
   - Vul project details in
   - Wacht tot database is aangemaakt

2. **Importeer Database Schema**
   - Ga naar SQL Editor in Supabase dashboard
   - Open `Database dumb/databasedump.sql`
   - Kopieer en voer uit in SQL Editor

3. **Update config.py**
   - Gebruik de nieuwe connection string van je nieuwe project

## Test Database Connectie

Na het updaten van de configuratie, test de connectie:

```bash
python test_database.py
```

## Troubleshooting

### "could not translate host name"
- Controleer of je internet verbinding hebt
- Controleer of de Supabase database nog actief is
- Probeer de connection pooler URL in plaats van direct connection

### "authentication failed"
- Controleer of het wachtwoord correct is
- Controleer of de database user bestaat
- Reset het wachtwoord in Supabase dashboard indien nodig

### "connection refused"
- Controleer of poort 5432 niet geblokkeerd is door firewall
- Probeer connection pooler op poort 6543
- Controleer of je IP adres toegang heeft tot Supabase

## Huidige Configuratie

```python
# app/config.py
class Config: 
    SECRET_KEY = 'sb_secret_Ft6fDkZhNVImBd_cgxFWZg_lCXrcbUa'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:GROUP10*PLACABOIS@db.kilpcevxhcwysfllheen.supabase.co:5432/postgres'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
```

## Belangrijke Bestanden

- `app/config.py` - Database configuratie
- `Database dumb/databasedump.sql` - Database schema en data
- `test_database.py` - Script om database connectie te testen
- `check_database_config.py` - Script om configuratie te controleren

