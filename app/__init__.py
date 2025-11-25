from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'sb_secret_Ft6fDkZhNVImBd_cgxFWZg_lCXrcbUa'
    
    from .routes import main
    app.register_blueprint(main)
    
    return app