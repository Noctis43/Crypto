import string

ALPHABET = string.ascii_uppercase

def cesar_encrypt(message, shift):
  result = ""
  shifts = [shift, shift + 1, shift + 2]
  for i, char in enumerate(message.upper()):
    if char in ALPHABET:
      index = ALPHABET.index(char)
      current_shift = shifts[i % len(shifts)]
      new_index = (index + current_shift) % len(ALPHABET)
      result += ALPHABET[new_index]
    else:
      result += char
  return result

def cesar_decrypt(message, shift):
  result = ""
  shifts = [shift, shift + 1, shift + 2]
  for i, char in enumerate(message.upper()):
    if char in ALPHABET:
      index = ALPHABET.index(char)
      current_shift = shifts[i % len(shifts)]
      new_index = (index - current_shift) % len(ALPHABET)
      result += ALPHABET[new_index]
    else:
      result += char
  return result