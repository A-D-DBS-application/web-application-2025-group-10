from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import ENUM
from datetime import datetime

db = SQLAlchemy()


# ENUM TYPES

probleem_type_enum = ENUM('Technisch', 'Esthetisch', 'Service/Levering', 'Andere', name='probleem_type', create_type=False)
klacht_status_enum = ENUM('Ingediend', 'In behandeling', 'Afgehandeld', name='klacht_status', create_type=False)
gebruikersrol_enum = ENUM('Admin', 'Key user', 'User', name='gebruikersrol', create_type=False)


# MODELS


class Businessunit(db.Model):
    __tablename__ = 'businessunit'
    businessunit_id = db.Column(db.BigInteger, primary_key=True)
    naam = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<Businessunit(id={self.businessunit_id}, naam='{self.naam}')>"

    

    # Relatie naar vertegenwoordigers die bij deze businessunit horen
    vertegenwoordigers = db.relationship('Gebruiker', backref='businessunit', lazy=True)

class Gebruiker(db.Model):
    __tablename__ = 'gebruiker'
    gebruiker_id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False, unique=True)
    rol = db.Column(gebruikersrol_enum, nullable=False)
    wachtwoord = db.Column(db.Text, nullable=False)
    telefoon = db.Column(db.Text)
    businessunit_id = db.Column(db.BigInteger, db.ForeignKey('businessunit.businessunit_id', onupdate='CASCADE'))
    
    def __repr__(self):
        return f"<Gebruiker(id={self.gebruiker_id}, naam='{self.naam}', email='{self.email}')>"


    # Relatie naar statushistoriek die door deze gebruiker is gewijzigd
    statushistoriek = db.relationship('StatusHistoriek', backref='gewijzigd_door_gebruiker', lazy=True)

    # Relatie naar klachten waarvoor deze gebruiker de verantwoordelijke is
    klachten = db.relationship('Klacht', backref='verantwoordelijke', lazy=True, foreign_keys='Klacht.verantwoordelijke_id')

class Klant(db.Model):
    __tablename__ = 'klant'
    klant_id = db.Column(db.Integer, primary_key=True)
    klantnaam = db.Column(db.Text, nullable=False)
    contactpersoon = db.Column(db.Text)
    email = db.Column(db.Text)
    telefoon =  db.Column(db.Text)
    adres = db.Column(db.Text)
    ondernemingsnummer = db.Column(db.BigInteger)

    def __repr__(self):
        return f"<Klant(id={self.klant_id}, naam='{self.klantnaam}')>"

    # Relaties naar orders en klachten
    orders = db.relationship('Order', backref='klant', lazy=True)
    klachten = db.relationship('Klacht', backref='klant', lazy=True)

class Order(db.Model):
    __tablename__ = 'order'
    order_nummer = db.Column(db.String(255), primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    klant_id = db.Column(db.Integer, db.ForeignKey('klant.klant_id'))

    def __repr__(self):
        return f"<Order(nummer='{self.order_nummer}', klant_id={self.klant_id})>"

    producten = db.relationship('Product', secondary='producten_order', lazy='dynamic', overlaps="orders,producten")

class Probleemcategorie(db.Model):
    __tablename__ = 'probleemcategorie'
    categorie_id = db.Column(db.Integer, primary_key=True)
    type = db.Column(probleem_type_enum, nullable=False)

    # Relatie naar klachten in deze categorie
    klachten = db.relationship('Klacht', backref='categorie', lazy=True)

class Klacht(db.Model):
    __tablename__ = 'klacht'
    klacht_id = db.Column(db.Integer, primary_key=True)
    verantwoordelijke_id = db.Column(db.Integer, db.ForeignKey('gebruiker.gebruiker_id', ondelete='SET NULL'))
    klant_id = db.Column(db.Integer, db.ForeignKey('klant.klant_id', ondelete='SET NULL'))
    categorie_id = db.Column(db.Integer, db.ForeignKey('probleemcategorie.categorie_id', ondelete='SET NULL'))
    order_nummer = db.Column(db.String(255), db.ForeignKey('order.order_nummer', ondelete='SET NULL'))
    mogelijke_oorzaak = db.Column(db.Text)
    bijlages = db.Column(db.Text)
    prioriteit = db.Column(db.Boolean, default=False)
    status = db.Column(klacht_status_enum, default='Ingediend')
    datum_melding = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    klacht_omschrijving = db.Column(db.Text)
    opmerking_status_wijziging = db.Column(db.Text)
    datum_laatst_bewerkt = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    businessunit_id = db.Column(db.BigInteger, db.ForeignKey('businessunit.businessunit_id', onupdate='CASCADE'))
    aantal_eenheden = db.Column(db.SmallInteger)
    artikelnummer = db.Column(db.Text, db.ForeignKey('product.artikel_nr', ondelete='SET NULL'))

    # Relatie naar statushistoriek
    statushistoriek = db.relationship('StatusHistoriek', backref='klacht', lazy=True, cascade='all, delete')
    
    # Relatie naar product (via artikelnummer)
    product = db.relationship('Product', backref='klachten', lazy=True, foreign_keys=[artikelnummer])
    
    # Relatie naar order (via ordernummer)
    order = db.relationship('Order', backref='klachten', lazy=True, foreign_keys=[order_nummer])
    
    # Relatie naar businessunit
    businessunit = db.relationship('Businessunit', backref='klachten', lazy=True, foreign_keys=[businessunit_id])

    @property
    def ondernemingsnummer(self):
        """Afleidbare toegang tot het ondernemingsnummer via de gekoppelde klant."""
        return self.klant.ondernemingsnummer if self.klant else None

class StatusHistoriek(db.Model):
    __tablename__ = 'statushistoriek'
    status_id = db.Column(db.Integer, primary_key=True)
    klacht_id = db.Column(db.Integer, db.ForeignKey('klacht.klacht_id', ondelete='CASCADE'))
    oude_status = db.Column(klacht_status_enum)
    nieuwe_status = db.Column(klacht_status_enum)
    gewijzigd_door = db.Column(db.Integer, db.ForeignKey('gebruiker.gebruiker_id'))
    opmerking = db.Column(db.Text)
    datum_wijziging = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)

class Product(db.Model):
    __tablename__ = 'product'
    artikel_nr = db.Column(db.Text, primary_key=True)
    naam = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<Product(artikel_nr={self.artikel_nr}, naam='{self.naam}')>"

    orders = db.relationship('Order', secondary='producten_order', lazy='dynamic', overlaps="orders,producten")

class Producten_Order(db.Model):
    __tablename__ = 'producten_order'
    order_nummer = db.Column(db.String(255), db.ForeignKey('order.order_nummer'), primary_key=True, nullable=False)
    artikel_nr = db.Column(db.Text, db.ForeignKey('product.artikel_nr'), primary_key=True, nullable=False)
    aantal = db.Column(db.Integer, nullable=False)

    order = db.relationship('Order', backref='product_orders', lazy=True, overlaps="orders,producten")
    product = db.relationship('Product', backref='order_links', lazy=True, overlaps="orders,producten")


    
