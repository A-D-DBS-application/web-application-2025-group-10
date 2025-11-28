from flask import Flask
from .config import Config
from .models import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize DB if you use it; this makes db available
    db.init_app(app)

    from .routes import main
    app.register_blueprint(main)
    
    # Optional: create DB tables in development - only if needed
    # with app.app_context():
    #     db.create_all()
    
    return app