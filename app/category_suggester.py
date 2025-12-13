import re
from typing import Dict, List

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

