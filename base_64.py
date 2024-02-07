from base64 import b64encode, b64decode

def encode(chaine):
    return b64encode(chaine.encode()).decode()

def decode(chaine):
    return b64decode(chaine).decode()

def main():
    print("Menu:\n\t1. Encoder en base 64\n\t2. Décoder en base 64\n3. Quitter\n\n")
    choix = input("\tVotre choix ?")
    if(choix == "1"):
        chaine = input("Entrez le chaine à encoder :")
        print(f"Resultat : {encode(chaine)}")
    elif(choix == "2"):
        chaine = input("Entrez le chaine à décoder :")
        print(f"Resultat : {decode(chaine)}")

main()
