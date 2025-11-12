from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import ENUM, JSONB
from datetime import datetime

db = SQLAlchemy()

# ============================
# ENUM TYPES
# ============================
probleem_type_enum = ENUM('Technisch', 'Esthetisch', 'Service/Levering', 'Andere', name='probleem_type', create_type=False)
klacht_status_enum = ENUM('Ingediend', 'Goedgekeurd', 'Afgewezen', 'In behandeling', 'Afgehandeld', name='klacht_status', create_type=False)
gebruikersrol_enum = ENUM('Vertegenwoordiger', 'General Manager', 'Internal Sales', name='gebruikersrol', create_type=False)

# ============================
# MODELS
# ============================

class Productiebedrijf(db.Model):
    __tablename__ = 'productiebedrijf'
    productiebedrijf_id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(255), nullable=False)
    adres = db.Column(db.String(255))
    contactpersoon = db.Column(db.String(255))

    # Relatie naar vertegenwoordigers die bij dit productiebedrijf horen
    vertegenwoordigers = db.relationship('Gebruiker', backref='productiebedrijf', lazy=True)

class Gebruiker(db.Model):
    __tablename__ = 'gebruiker'
    gebruiker_id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False, unique=True)
    rol = db.Column(gebruikersrol_enum, nullable=False)
    wachtwoord = db.Column(db.Text, nullable=False)
    telefoon = db.Column(db.SmallInteger)
    productiebedrijf_id = db.Column(db.Integer, db.ForeignKey('productiebedrijf.productiebedrijf_id', onupdate='CASCADE'))

    # Relatie naar statushistoriek die door deze gebruiker is gewijzigd
    statushistoriek = db.relationship('StatusHistoriek', backref='gewijzigd_door_gebruiker', lazy=True)

    # Relatie naar klachten waarvoor deze gebruiker de vertegenwoordiger is
    klachten = db.relationship('Klacht', backref='vertegenwoordiger', lazy=True, foreign_keys='Klacht.vertegenwoordiger_id')

class Klant(db.Model):
    __tablename__ = 'klant'
    klant_id = db.Column(db.Integer, primary_key=True)
    klantnaam = db.Column(db.Text, nullable=False)
    contactpersoon = db.Column(db.Text)
    email = db.Column(db.Text)
    telefoon = db.Column(db.SmallInteger)

    # Relaties naar orders en klachten
    orders = db.relationship('Order', backref='klant', lazy=True)
    klachten = db.relationship('Klacht', backref='klant', lazy=True)

class Order(db.Model):
    __tablename__ = 'order'
    order_id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    klant_id = db.Column(db.Integer, db.ForeignKey('klant.klant_id'))

class Probleemcategorie(db.Model):
    __tablename__ = 'probleemcategorie'
    categorie_id = db.Column(db.Integer, primary_key=True)
    type = db.Column(probleem_type_enum, nullable=False)

    # Relatie naar klachten in deze categorie
    klachten = db.relationship('Klacht', backref='categorie', lazy=True)

class Klacht(db.Model):
    __tablename__ = 'klacht'
    klacht_id = db.Column(db.Integer, primary_key=True)
    vertegenwoordiger_id = db.Column(db.Integer, db.ForeignKey('gebruiker.gebruiker_id', ondelete='SET NULL'))
    klant_id = db.Column(db.Integer, db.ForeignKey('klant.klant_id', ondelete='SET NULL'))
    categorie_id = db.Column(db.Integer, db.ForeignKey('probleemcategorie.categorie_id', ondelete='SET NULL'))
    status_platen = db.Column(db.Text)
    mogelijke_oorzaak = db.Column(db.Text)
    bijlages = db.Column(JSONB)
    prioriteit = db.Column(db.Boolean, default=False)
    status = db.Column(klacht_status_enum, default='Ingediend')
    datum_melding = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    reden_afwijzing = db.Column(db.Text)
    gm_opmerking = db.Column(db.Text)
    datum_laatst_bewerkt = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)

    # Relatie naar statushistoriek
    statushistoriek = db.relationship('StatusHistoriek', backref='klacht', lazy=True, cascade='all, delete')

class StatusHistoriek(db.Model):
    __tablename__ = 'statushistoriek'
    status_id = db.Column(db.Integer, primary_key=True)
    klacht_id = db.Column(db.Integer, db.ForeignKey('klacht.klacht_id', ondelete='CASCADE'))
    oude_status = db.Column(klacht_status_enum)
    nieuwe_status = db.Column(klacht_status_enum)
    gewijzigd_door = db.Column(db.Integer, db.ForeignKey('gebruiker.gebruiker_id'))
    opmerking = db.Column(db.Text)
    datum_wijziging = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)