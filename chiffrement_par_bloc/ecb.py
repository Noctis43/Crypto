def xor_cle_repetee(data, cle):
  resultat = []
  if len(cle) <= 0:
    raise ValueError("La clé ne peut pas être vide.")
    return bytes(resultat)
  for i , octet in enumerate(data):
    crypted_octet = octet ^ cle[i % len(cle)]
    resultat.append(crypted_octet)
  return bytes(resultat)

def ecb(data, cle):
  resultat =b""
  data = bytes(data)
  for c in range(0, len(data), 8):
    bloc = data[c:c+8]
    if len(bloc) < 8:
      bloc = bloc + b"\x00" * (8 - len(bloc))
    resultat += xor_cle_repetee(bloc, cle)
  return bytes(resultat[:len(data)])

def lire_fichier(nom_fichier):
  with open(nom_fichier, "rb") as f:
    return f.read()

def ecrire_fichier(nom_fichier, data):
  with open(nom_fichier, "wb") as f:
    f.write(data)

def chiffrement_fichier(nom_entree, nom_sortie, cle):
  data = lire_fichier(nom_entree)
  data_chiffree = ecb(data, cle)
  ecrire_fichier(nom_sortie, data_chiffree)

def dechiffrement_fichier(nom_entree, nom_sortie, cle):
  data = lire_fichier(nom_entree)
  data_dechiffree = ecb(data, cle)
  ecrire_fichier(nom_sortie, data_dechiffree)

def verifier_chiffrement(nom_fichier_original, nom_fichier_chiffre, nom_fichier_dechiffre, cle):
  chiffrement_fichier(nom_fichier_original, nom_fichier_chiffre, cle)
  dechiffrement_fichier(nom_fichier_chiffre, nom_fichier_dechiffre, cle)
  original_data = lire_fichier(nom_fichier_original)
  decrypted_data = lire_fichier(nom_fichier_dechiffre)
  return original_data == decrypted_data
