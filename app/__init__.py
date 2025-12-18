from flask import Flask
from .config import Config
from .models import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Dit checkt de configuratie en geef waarschuwingen
    Config.check_config()
    
    # Start DB als je het gebruikt
    db.init_app(app)
    
    from .routes import main
    app.register_blueprint(main)
    
    return app