# Quick Fix: Database IPv4 Probleem

## Het Probleem
Je Supabase direct connection is **niet IPv4 compatible**, daarom krijg je de fout:
```
could not translate host name "db.kilpcevxhcwysfllheen.supabase.co" to address
```

## De Oplossing: Session Pooler

### Stap 1: Krijg Session Pooler Connection String

In je Supabase dashboard:
1. Klik op **"Pooler settings"** knop (in de modal die je ziet)
2. OF verander de **"Method"** dropdown naar **"Session mode"**
3. Kopieer de connection string die eruit ziet als:
   ```
   postgresql://postgres.kilpcevxhcwysfllheen:[YOUR-PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres
   ```

### Stap 2: Update Configuratie

**Optie A: Met script (aanbevolen)**
```bash
python fix_database_ipv4.py "postgresql://postgres.kilpcevxhcwysfllheen:GROUP10*PLACABOIS@aws-0-eu-central-1.pooler.supabase.com:5432/postgres"
```

**Optie B: Handmatig**
Open `app/config.py` en vervang regel 3:
```python
# OUD (niet IPv4 compatible):
SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:GROUP10*PLACABOIS@db.kilpcevxhcwysfllheen.supabase.co:5432/postgres'

# NIEUW (Session Pooler - IPv4 compatible):
SQLALCHEMY_DATABASE_URI = 'postgresql://postgres.kilpcevxhcwysfllheen:GROUP10*PLACABOIS@aws-0-eu-central-1.pooler.supabase.com:5432/postgres'
```

**LET OP:** Vervang `eu-central-1` met je eigen regio (staat in de connection string).

### Stap 3: Test

```bash
python test_database.py
```

Als het werkt, zie je:
```
[OK] Database connectie succesvol!
```

### Stap 4: Start Applicatie

```bash
python run.py
```

## Belangrijk

- **Session Pooler** werkt met IPv4 netwerken
- **Direct connection** werkt alleen met IPv6
- Gebruik altijd de **Session Pooler** voor productie applicaties

