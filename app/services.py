"""
Service layer voor herbruikbare database logica.
Alle database operaties via SQLAlchemy ORM.
"""
from .models import (
    db, Businessunit, Gebruiker, Klant, Order, Product, 
    Probleemcategorie, Klacht, StatusHistoriek
)
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import uuid


# BUSINESSUNIT SERVICES


def get_businessunit_by_id(bu_id):
    """Haal businessunit op via ID."""
    if not bu_id:
        return None
    try:
        return db.session.get(Businessunit, int(bu_id))
    except (ValueError, TypeError):
        return None


def get_businessunit_name(bu_id):
    """Haal businessunit naam op via ID."""
    bu = get_businessunit_by_id(bu_id)
    return bu.naam if bu else ''


def get_businessunits_list():
    """Haal alle businessunit namen op, gesorteerd."""
    try:
        rows = db.session.query(Businessunit.naam).order_by(Businessunit.naam).all()
        return [r[0] for r in rows if r and r[0]]
    except Exception as e:
        print(f"Warning: kon businessunits niet ophalen: {e}")
        return []


def resolve_or_create_businessunit(value):
    """Los businessunit op via ID of naam, of maak nieuwe aan."""
    if not value:
        return None
    try:
        # Probeer als ID
        return int(value)
    except (ValueError, TypeError):
        pass
    
    naam = str(value).strip()
    if not naam:
        return None
    
    try:
        # Zoeken
        existing = db.session.query(Businessunit).filter_by(naam=naam).first()
        if existing:
            return existing.businessunit_id
        
        # Maak nieuwe aan
        new_bu = Businessunit(naam=naam)
        db.session.add(new_bu)
        db.session.commit()
        return new_bu.businessunit_id
    except Exception as e:
        print(f"resolve_or_create_businessunit error: {e}")
        db.session.rollback()
        return None



# GEBRUIKER SERVICES


def get_user_by_email(email):
    """Haal gebruiker op via email (case-insensitive)."""
    if not email:
        return None
    try:
        # Zoeken maar negeren van hoofdletters 
        return db.session.query(Gebruiker).filter(
            db.func.lower(Gebruiker.email) == db.func.lower(email.strip())
        ).first()
    except Exception as e:
        print(f"Warning: get_user_by_email failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def get_user_by_id(user_id):
    """Haal gebruiker op via ID."""
    if not user_id:
        return None
    try:
        return db.session.get(Gebruiker, int(user_id))
    except (ValueError, TypeError):
        return None


def get_users_by_roles(roles=None, businessunit_id=None):
    """Haal gebruikers op gefilterd op rol en/of businessunit."""
    try:
        query = db.session.query(Gebruiker)
        if roles:
            query = query.filter(Gebruiker.rol.in_(roles))
        if businessunit_id:
            query = query.filter_by(businessunit_id=businessunit_id)
        return query.all()
    except Exception as e:
        print(f"Warning: get_users_by_roles failed: {e}")
        return []


def get_all_users():
    """Haal alle gebruikers op."""
    try:
        return db.session.query(Gebruiker).all()
    except Exception as e:
        print(f"Warning: get_all_users failed: {e}")
        return []



# KLANT SERVICES


def get_klant_by_id(klant_id):
    """Haal klant op via ID."""
    if not klant_id:
        return None
    try:
        return db.session.get(Klant, int(klant_id))
    except (ValueError, TypeError):
        return None


def get_klant_by_name(klantnaam):
    """Haal klant op via naam (case-insensitive)."""
    if not klantnaam:
        return None
    try:
        return db.session.query(Klant).filter(
            db.func.lower(Klant.klantnaam) == klantnaam.lower()
        ).first()
    except Exception as e:
        print(f"Warning: get_klant_by_name failed: {e}")
        return None


def get_all_klanten():
    """Haal alle klanten op."""
    try:
        return db.session.query(Klant).all()
    except Exception as e:
        print(f"Warning: get_all_klanten failed: {e}")
        return []


def create_klant(klantnaam):
    """Maak nieuwe klant aan."""
    if not klantnaam:
        return None
    try:
        new_klant = Klant(klantnaam=klantnaam.strip())
        db.session.add(new_klant)
        db.session.commit()
        return new_klant
    except Exception as e:
        print(f"Warning: create_klant failed: {e}")
        db.session.rollback()
        return None



# PRODUCT SERVICES


def get_product_by_artikelnummer(artikel_nr):
    """Haal product op via artikelnummer."""
    if not artikel_nr:
        return None
    try:
        # Convert to string to ensure consistency
        artikel_nr_str = str(artikel_nr).strip() if artikel_nr else None
        if not artikel_nr_str:
            return None
        return db.session.get(Product, artikel_nr_str)
    except (ValueError, TypeError):
        return None


def ensure_product_exists(artikelnummer, artikelnaam=None):
    """Zorg dat product bestaat, maak aan indien nodig."""
    if not artikelnummer:
        return None
    # Convert to string to ensure consistency
    artikel_nr = str(artikelnummer).strip() if artikelnummer else None
    if not artikel_nr:
        return None
    
    try:
        # Checken of het bestaat
        product = get_product_by_artikelnummer(artikel_nr)
        if product:
            return artikel_nr
        
        # Een nieuwe aanmaken
        naam = artikelnaam.strip() if artikelnaam else f"Product {artikel_nr}"
        new_product = Product(artikel_nr=artikel_nr, naam=naam)
        db.session.add(new_product)
        db.session.commit()
        return artikel_nr
    except Exception as e:
        print(f"Warning: ensure_product_exists failed: {e}")
        db.session.rollback()
        return artikel_nr



# ORDER SERVICES


def get_order_by_nummer(order_nummer):
    """Haal order op via ordernummer."""
    if not order_nummer:
        return None
    try:
        return db.session.get(Order, str(order_nummer))
    except Exception:
        return None


def ensure_order_exists(order_nummer, klant_id=None):
    """Zorg dat order bestaat, maak aan indien nodig."""
    if not order_nummer:
        return None
    try:
        # Checken als het bestaat
        order = get_order_by_nummer(order_nummer)
        if order:
            return order_nummer
        
        # Een nieuwe aanmaken
        new_order = Order(order_nummer=str(order_nummer))
        if klant_id:
            try:
                new_order.klant_id = int(klant_id)
            except (ValueError, TypeError):
                pass
        db.session.add(new_order)
        db.session.commit()
        return order_nummer
    except Exception as e:
        print(f"Warning: ensure_order_exists failed: {e}")
        db.session.rollback()
        return order_nummer


def get_all_orders():
    """Haal alle orders op, gesorteerd op ordernummer."""
    try:
        return db.session.query(Order).order_by(Order.order_nummer).all()
    except Exception as e:
        print(f"Warning: get_all_orders failed: {e}")
        return []


def get_all_products():
    """Haal alle producten op, gesorteerd op artikelnummer."""
    try:
        return db.session.query(Product).order_by(Product.artikel_nr).all()
    except Exception as e:
        print(f"Warning: get_all_products failed: {e}")
        return []


# PROBLEEMCATEGORIE SERVICES


def get_categorieen_list():
    """Haal alle categorieën op met ID en type."""
    try:
        rows = db.session.query(Probleemcategorie.categorie_id, Probleemcategorie.type).order_by(Probleemcategorie.type).all()
        return [
            {"categorie_id": cid, "type": ctype}
            for cid, ctype in rows
            if cid is not None and ctype is not None
        ]
    except Exception as e:
        print(f"Warning: get_categorieen_list failed: {e}")
        return []


def get_categorie_by_id(categorie_id):
    """Haal categorie op via ID."""
    if not categorie_id:
        return None
    try:
        return db.session.get(Probleemcategorie, int(categorie_id))
    except (ValueError, TypeError):
        return None



# KLACHT SERVICES


def get_klacht_by_id(klacht_id):
    """Haal klacht op via ID met alle relaties."""
    if not klacht_id:
        return None
    try:
        return db.session.query(Klacht).filter_by(klacht_id=klacht_id).first()
    except Exception as e:
        print(f"Warning: get_klacht_by_id failed: {e}")
        return None


def get_klachten_for_user(user_id, role, businessunit_id=None):
    """Haal klachten op voor gebruiker (gefilterd op rol)."""
    try:
        query = db.session.query(Klacht)
        
        if role == 'User':
            query = query.filter_by(verantwoordelijke_id=user_id)
        elif role == 'Key user' and businessunit_id:
            query = query.filter_by(businessunit_id=businessunit_id)
        # Admin ziet alles, dus geen filter
        
        return query.order_by(Klacht.datum_melding.desc()).all()
    except Exception as e:
        print(f"Warning: get_klachten_for_user failed: {e}")
        return []


def get_all_klachten():
    """Haal alle klachten op met eager loading van relaties."""
    try:
        from sqlalchemy.orm import joinedload
        return db.session.query(Klacht).options(
            joinedload(Klacht.verantwoordelijke),
            joinedload(Klacht.klant),
            joinedload(Klacht.categorie),
            joinedload(Klacht.businessunit)
        ).order_by(Klacht.datum_melding.desc()).all()
    except Exception as e:
        print(f"Warning: get_all_klachten failed: {e}")
        import traceback
        traceback.print_exc()
        return []



# STATUSHISTORIEK SERVICES


def get_statushistoriek_for_klacht(klacht_id):
    """Haal statushistoriek op voor een klacht."""
    if not klacht_id:
        return []
    try:
        return db.session.query(StatusHistoriek).filter_by(
            klacht_id=klacht_id
        ).order_by(StatusHistoriek.datum_wijziging.desc()).all()
    except Exception as e:
        print(f"Warning: get_statushistoriek_for_klacht failed: {e}")
        return []


def create_statushistoriek(klacht_id, oude_status, nieuwe_status, gewijzigd_door, opmerking=None):
    """Maak nieuwe statushistoriek entry aan."""
    try:
        hist = StatusHistoriek(
            klacht_id=klacht_id,
            oude_status=oude_status,
            nieuwe_status=nieuwe_status,
            gewijzigd_door=gewijzigd_door,
            opmerking=opmerking
        )
        db.session.add(hist)
        db.session.commit()
        return hist
    except Exception as e:
        print(f"Warning: create_statushistoriek failed: {e}")
        db.session.rollback()
        return None

