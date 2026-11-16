import * from AES_128

def ctr_encrypt(message, key, iv):
  if len(key) != 16:
    raise ValueError("La clé doit être de 16 octets pour AES-128.")
  if len(iv) != 16:
    raise ValueError("Le vecteur d'initialisation (IV) doit être de 16 octets pour AES-128.")
  resultat = bytearray()
  compteur = int.from_bytes(iv, byteorder='big')
  position = 0

  while position < len(message):
    bloc_compteur = compteur.to_bytes(16, byteorder='big')
    keystream = aes_encrypt(bloc_compteur, key)
    bloc_message = message[position:position + 16]
    bloc_chiffre = bytes([bloc_message[i] ^ keystream[i] for i in range(len(bloc_message))])
    resultat.extend(bloc_chiffre)
    compteur  = (compteur + 1) % (2**128)
  return bytes(resultat)

def ctr_decrypt(message_chiffre, key, iv):
  return ctr_encrypt(message_chiffre, key, iv)