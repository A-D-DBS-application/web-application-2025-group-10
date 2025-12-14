import re
from typing import Dict, List

from .models import Klacht, Probleemcategorie, db

# Kernwoorden per probleemcategorie; eenvoudig uitbreidbaar
CATEGORY_KEYWORDS: Dict[str, List[str]] = {
    "Technisch": [
        "constructie",
        "verbinding",
        "scheur",
        "barst",
        "krom",
        "los",
        "delaminatie",
        "sterkte",
        "stabiliteit",
        "montage",
        "schroef",
        "bout",
        "defect",
        "kapot",
        "vervorming",
        "draagkracht",
    ],
    "Esthetisch": [
        "kleur",
        "verkleuring",
        "vlek",
        "kras",
        "deuk",
        "afwerking",
        "splinter",
        "ruw",
        "lak",
        "coating",
        "oneffen",
        "noest",
        "glans",
    ],
    "Service/Levering": [
        "levering",
        "transport",
        "bezorging",
        "te laat",
        "vertraging",
        "verzending",
        "planning",
        "communicatie",
        "afspraak",
        "chauffeur",
        "pakbon",
        "factuur",
        "order",
        "logistiek",
    ],
    "Andere": [],
}


def _normalize_text(value: str) -> str:
    """Lowercase en verwijder leestekens/extra spaties."""
    if not value:
        return ""
    lowered = value.lower()
    cleaned = re.sub(r"[^\w\s]", " ", lowered)
    collapsed = re.sub(r"\s+", " ", cleaned)
    return collapsed.strip()


def suggest_probleemcategorie(klacht_omschrijving: str, mogelijke_oorzaak: str) -> str:
    """
    Stel een probleemcategorie voor op basis van sleutelwoorden in de gecombineerde tekst.

    - combineert klacht_omschrijving en mogelijke_oorzaak
    - normaliseert de tekst
    - telt keyword hits per categorie
    - retourneert de categorie met hoogste score of 'Andere' als er geen matches zijn
    """
    combined = " ".join(
        part for part in [_normalize_text(klacht_omschrijving), _normalize_text(mogelijke_oorzaak)] if part
    ).strip()

    if not combined:
        return "Andere"

    scores: Dict[str, int] = {}
    for categorie, keywords in CATEGORY_KEYWORDS.items():
        score = 0
        for keyword in keywords:
            # Gebruik word boundaries zodat we hele woorden meten
            pattern = r"\b" + re.escape(keyword.lower()) + r"\b"
            score += len(re.findall(pattern, combined))
        scores[categorie] = score

    # Kies categorie met hoogste score; fallback naar "Andere" bij 0 hits
    best_categorie = max(scores.items(), key=lambda item: item[1])[0]
    if scores.get(best_categorie, 0) == 0:
        return "Andere"
    return best_categorie


def suggest_probleemcategorie_contextual_sqlalchemy(
    omschrijving: str, oorzaak: str, businessunit_id: int = None
) -> str:
    """
    Geef een voorstel voor een probleemcategorie op basis van:
    1. trefwoordenanalyse;
    2. historische frequentie binnen dezelfde businessunit;
    3. recentste klacht (datum_melding + hoogste klacht_id).
    """
    # 1) combineer en normaliseer tekst
    combined = " ".join(
        part for part in [_normalize_text(omschrijving), _normalize_text(oorzaak)] if part
    ).strip()
    if not combined:
        return "Andere"

    # 2) keyword scores
    # Sla "Andere" over in de telling (heeft geen keywords); enkel positieve scores mogen verder.
    scores: Dict[str, int] = {}
    for categorie, keywords in CATEGORY_KEYWORDS.items():
        if not keywords:
            continue
        score = sum(
            len(re.findall(r"\b" + re.escape(keyword.lower()) + r"\b", combined))
            for keyword in keywords
        )
        scores[categorie] = score

    max_score = max(scores.values()) if scores else 0
    if max_score == 0:
        return "Andere"

    # Alleen categorieën met een positieve score zijn kandidaten
    candidates = [cat for cat, sc in scores.items() if sc == max_score and sc > 0]
    if len(candidates) == 1:
        return candidates[0]

    # 3) Historische frequentie binnen businessunit
    freq: Dict[str, int] = {}
    for cat in candidates:
        pc = Probleemcategorie.query.filter_by(type=cat).first()
        if pc is None:
            freq[cat] = 0
        else:
            q = db.session.query(Klacht).filter_by(categorie_id=pc.categorie_id)
            if businessunit_id is not None:
                q = q.filter_by(businessunit_id=businessunit_id)
            count = q.count()
            freq[cat] = count
    max_freq = max(freq.values()) if freq else 0
    freq_candidates = [cat for cat in candidates if freq.get(cat, 0) == max_freq]
    if len(freq_candidates) == 1 and max_freq > 0:
        return freq_candidates[0]

    # 4) Tie-breaker: meest recent via hoogste klacht_id (proxy voor meest recent)
    latest_cat = None
    latest_date = None
    latest_id = None
    for cat in freq_candidates or candidates:
        pc = Probleemcategorie.query.filter_by(type=cat).first()
        if pc:
            q = (
                db.session.query(Klacht)
                .filter_by(categorie_id=pc.categorie_id)
                .order_by(Klacht.klacht_id.desc())
            )
            if businessunit_id is not None:
                q = q.filter_by(businessunit_id=businessunit_id)
            latest = q.first()
            if latest:
                k_id = latest.klacht_id
                if (latest_id is None) or (k_id > latest_id):
                    latest_id = k_id
                    latest_cat = cat

    # 5) Veilige fallback
    return latest_cat or "Andere"
