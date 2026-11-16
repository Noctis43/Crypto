def xor_encrypt(data, cle):
  resultat = []
  for octet in data:
    crypted_octet = octet ^ cle
    resultat.append(crypted_octet)
  return bytes(resultat)

def xor_decrypt(data, cle):
  resultat = []
  for octet in data:
    decrypted_octet = octet ^ cle
    resultat.append(decrypted_octet)
  return bytes(resultat)