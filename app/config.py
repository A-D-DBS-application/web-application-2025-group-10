import os
from dotenv import load_dotenv

# Laad environment variables uit env file
load_dotenv()

class Config: 
    SECRET_KEY = 'sb_secret_Ft6fDkZhNVImBd_cgxFWZg_lCXrcbUa'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres.kilpcevxhcwysfllheen:GROUP10*PLACABOIS@aws-1-eu-central-1.pooler.supabase.com:5432/postgres'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Dit is onze Supabase Storage configuratie
    SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://kilpcevxhcwysfllheen.supabase.co')
    SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')
    SUPABASE_ANON_KEY = os.getenv('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtpbHBjZXZ4aGN3eXNmbGxoZWVuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjA2NDAzMjUsImV4cCI6MjA3NjIxNjMyNX0.OYGug034pb1c8tvN15uzic-IxWQW-ZknuNE3strNKxk')
    SUPABASE_KEY = SUPABASE_SERVICE_KEY or SUPABASE_ANON_KEY
    SUPABASE_STORAGE_BUCKET = 'bijlages'  
    
    # Waarschuwing
    @classmethod
    def check_config(cls):
        """Check configuratie en geef waarschuwingen."""
        if not cls.SUPABASE_SERVICE_KEY:
            print("=" * 80)
            print("WAARSCHUWING: SUPABASE_SERVICE_KEY niet gevonden in .env bestand!")
            print("Uploads zullen waarschijnlijk falen met 'row-level security policy' error.")
            print("Oplossing: Maak een .env bestand aan met SUPABASE_SERVICE_KEY.")
            print("=" * 80)