import json
import requests

from app.services.parsers.eu_parser import parse_eu_xml
from app.services.parsers.france_gel_parser import parse_france_gel_json


EU_XML_URL = "https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw"
FR_GEL_JSON_URL = "https://gels-avoirs.dgtresor.gouv.fr/ApiPublic/api/v1/publication/derniere-publication-fichier-json"


print("=== TEST UE XML ===")
try:
    r = requests.get(EU_XML_URL, timeout=90)
    print("HTTP UE =", r.status_code)
    print("Taille UE =", len(r.content))
    print("Début UE :")
    print(r.content[:500].decode("utf-8", errors="replace"))

    entries = parse_eu_xml(r.content)
    print("NOMBRE ENTREES UE =", len(entries))

    if entries:
        print("PREMIERE ENTREE UE =")
        print(entries[0])

except Exception as e:
    print("ERREUR TEST UE =", str(e))


print("\n=== TEST FRANCE GEL JSON ===")
try:
    r = requests.get(FR_GEL_JSON_URL, timeout=90)
    print("HTTP FR_GEL =", r.status_code)
    print("Taille FR_GEL =", len(r.content))
    print("Début FR_GEL :")
    print(r.content[:1000].decode("utf-8", errors="replace"))

    try:
        data = json.loads(r.content.decode("utf-8-sig"))
        print("TYPE JSON =", type(data))

        if isinstance(data, dict):
            print("CLES JSON =", list(data.keys())[:30])

    except Exception as json_error:
        print("ERREUR LECTURE JSON =", str(json_error))

    entries = parse_france_gel_json(r.content)
    print("NOMBRE ENTREES FR_GEL =", len(entries))

    if entries:
        print("PREMIERE ENTREE FR_GEL =")
        print(entries[0])

except Exception as e:
    print("ERREUR TEST FR_GEL =", str(e))
