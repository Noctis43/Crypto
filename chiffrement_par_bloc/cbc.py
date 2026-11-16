def xor_cle_repetee(data, cle):
  resultat = []
  if len(cle) <= 0:
    raise ValueError("La clé ne peut pas être vide.")
    return bytes(resultat)
  for i, octet in enumerate(data):
    crypted_octet = octet ^ cle[i % len(cle)]
    resultat.append(crypted_octet)
  return bytes(resultat)

def rembourage_bloc(data, taille_bloc):
  reste = len(data) % taille_bloc
  if reste == 0:
    nombre_octets_rembourage = taille_bloc
  else:
    nombre_octets_rembourage = taille_bloc - reste
  return data + bytes([nombre_octets_rembourage] * nombre_octets_rembourage)

def retirer_rembourage_bloc(data):
  nombre_octets_rembourage = data[-1]
  return data[:-nombre_octets_rembourage]

def xor_bloc(bloc1, bloc2):
  resultat = []
  for i in range(len(bloc1)):
    resultat.append(bloc1[i] ^ bloc2[i])
  return bytes(resultat)

def cbc(data, cle, iv, taille_bloc):
  data = rembourage_bloc(data, taille_bloc)
  resultat = b""
  bloc_precedent = iv
  for i in range(0, len(data), taille_bloc):
    bloc_courant = data[i:i+taille_bloc]
    bloc_xor = xor_bloc(bloc_courant, bloc_precedent)
    bloc_chiffre = xor_cle_repetee(bloc_xor, cle)
    resultat += bloc_chiffre
    bloc_precedent = bloc_chiffre
  return resultat

def cbc_dechiffrement(data, cle, iv, taille_bloc):
  resultat = b""
  bloc_precedent = iv
  for i in range(0, len(data), taille_bloc):
    bloc_chiffre = data[i:i+taille_bloc]
    bloc_dechiffre = xor_cle_repetee(bloc_chiffre, cle)
    bloc_xor = xor_bloc(bloc_dechiffre, bloc_precedent)
    resultat += bloc_xor
    bloc_precedent = bloc_chiffre
  return retirer_rembourage_bloc(resultat)