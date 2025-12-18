import os
from dotenv import load_dotenv

# Laad environment variables uit .env file (als deze bestaat)
load_dotenv()

class Config: 
    SECRET_KEY = 'sb_secret_Ft6fDkZhNVImBd_cgxFWZg_lCXrcbUa'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres.kilpcevxhcwysfllheen:GROUP10*PLACABOIS@aws-1-eu-central-1.pooler.supabase.com:5432/postgres'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Supabase Storage configuratie
    SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://kilpcevxhcwysfllheen.supabase.co')
    # Gebruik service_role key voor uploads (heeft meer rechten dan anon key)
    # Voor productie: gebruik environment variable SUPABASE_SERVICE_KEY
    SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')
    SUPABASE_ANON_KEY = os.getenv('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtpbHBjZXZ4aGN3eXNmbGxoZWVuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjA2NDAzMjUsImV4cCI6MjA3NjIxNjMyNX0.OYGug034pb1c8tvN15uzic-IxWQW-ZknuNE3strNKxk')
    # Gebruik service role key als die beschikbaar is, anders anon key (fallback)
    SUPABASE_KEY = SUPABASE_SERVICE_KEY or SUPABASE_ANON_KEY
    SUPABASE_STORAGE_BUCKET = 'bijlages'  # Naam van de bucket zoals getoond in de screenshot
    
    # Waarschuwing bij startup als service role key niet is ingesteld
    @classmethod
    def check_config(cls):
        """Check configuratie en geef waarschuwingen."""
        if not cls.SUPABASE_SERVICE_KEY:
            print("=" * 80)
            print("WAARSCHUWING: SUPABASE_SERVICE_KEY niet gevonden in .env bestand!")
            print("Uploads zullen waarschijnlijk falen met 'row-level security policy' error.")
            print("Oplossing: Maak een .env bestand aan met SUPABASE_SERVICE_KEY.")
            print("=" * 80)