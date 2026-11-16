def chiffrer(data, cle):
  resultat = []
  index = 0
  for octet in data:
    current_cle = cle[index % len(cle)]
    crypted_octet = (octet + current_cle) % 256
    index += 1
    resultat.append(crypted_octet)
  return bytes(resultat)

def dechiffrer(data, cle):
  resultat = []
  index = 0
  for octet in data:
    current_cle = cle[index % len(cle)]
    decrypted_octet = (octet - current_cle) % 256
    index += 1
    resultat.append(decrypted_octet)
  return bytes(resultat)

def lire_fichier(nom_fichier):
  with open(nom_fichier, "rb") as f:
    return f.read()

def ecrire_fichier(nom_fichier, data):
  with open(nom_fichier, "wb") as f:
    f.write(data)

def chiffrement_fichier(nom_entree, nom_sortie, cle):
  data = lire_fichier(nom_entree)
  data_chiffree = chiffrer(data, cle)
  ecrire_fichier(nom_sortie, data_chiffree)

def dechiffrement_fichier(nom_entree, nom_sortie, cle):
  data = lire_fichier(nom_entree)
  data_dechiffree = dechiffrer(data, cle)
  ecrire_fichier(nom_sortie, data_dechiffree)

def verifier_chiffrement(nom_fichier_original, nom_fichier_chiffre, nom_fichier_dechiffre, cle):
  chiffrement_fichier(nom_fichier_original, nom_fichier_chiffre, cle)
  dechiffrement_fichier(nom_fichier_chiffre, nom_fichier_dechiffre, cle)
  original_data = lire_fichier(nom_fichier_original)
  decrypted_data = lire_fichier(nom_fichier_dechiffre)
  return original_data == decrypted_data