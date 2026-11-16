import * from AES_128

def cfb_encrypt(message, key, iv):
  if len(key) != 16:
    raise ValueError("La clé doit être de 16 octets pour AES-128.")
  if len(iv) != 16:
    raise ValueError("Le vecteur d'initialisation (IV) doit être de 16 octets pour AES-128.")
  resultat = bytearray()
  register = iv
  position = 0

  while position < len(message):
    bloc_aes = aes_encrypt(register, key)
    bloc_message = message[position:position + 16]
    bloc_chiffre = bytes([bloc_message[i] ^ bloc_aes[i] for i in range(len(bloc_message))])
    resultat.extend(bloc_chiffre)
    
    if len(bloc_chiffre) == 16:
      register = bloc_chiffre
    position += 16
  return bytes(resultat)

def cfb_decrypt(message_chiffre, key, iv):
  if len(key) != 16:
    raise ValueError("La clé doit être de 16 octets pour AES-128.")
  if len(iv) != 16:
    raise ValueError("Le vecteur d'initialisation (IV) doit être de 16 octets pour AES-128.")
  resultat = bytearray()
  register = iv
  position = 0

  while position < len(message_chiffre):
    bloc_aes = aes_encrypt(register, key)
    bloc_chiffre = message_chiffre[position:position + 16]
    bloc_claire = bytes([bloc_chiffre[i] ^ bloc_aes[i] for i in range(len(bloc_chiffre))])
    resultat.extend(bloc_claire)
    
    if len(bloc_chiffre) == 16:
      register = bloc_chiffre
    position += 16
  return bytes(resultat)
