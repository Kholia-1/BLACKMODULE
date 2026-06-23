import requests
from app.services.parsers.uksl_parser import parse_uksl_csv

url = "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv"

print("Téléchargement UKSL...")
response = requests.get(url, timeout=60)

print("HTTP =", response.status_code)
print("Taille fichier =", len(response.content), "octets")

print("\nDébut du fichier téléchargé :")
print(response.content[:500].decode("utf-8-sig", errors="replace"))

entries = parse_uksl_csv(response.content)

print("\nNOMBRE_ENTREES =", len(entries))

if entries:
    print("\nPREMIERE ENTREE :")
    first = entries[0]

    for key, value in first.items():
        print(key, "=", value)
else:
    print("AUCUNE_ENTREE")
