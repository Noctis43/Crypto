import hashlib

def pgcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a

def euclide_etendu(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = euclide_etendu(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def inverse_modulaire(a: int, n: int) -> int:
    g, x, _ = euclide_etendu(a, n)
    if g != 1:
        raise ValueError("L'inverse modulaire n'existe pas.")
    return x % n

def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True

def puissance_modulaire(base: int, exposant: int, mod: int) -> int:
    if mod <= 0:
        raise ValueError("Le module doit être un entier positif.")
    if exposant < 0:
        raise ValueError("L'exposant doit être un entier non négatif.")
    resultat = 1 % mod
    base = base % mod

    while exposant > 0:
        if exposant % 2 == 1:
            resultat = (resultat * base) % mod
        base = (base * base) % mod
        exposant //= 2
    return resultat

def genere_cle_rsa(p: int, q: int, e: int = 17):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Les nombres p et q doivent être des nombres premiers.")
    if p == q:
        raise ValueError("Les nombres p et q doivent être distincts.")
    n = p * q
    phi = (p - 1) * (q - 1)

    if not (1 < e < phi) and pgcd(e, phi) == 1:
        raise ValueError("L'exposant e doit être un entier positif inférieur à φ(n) et premier avec φ(n).")
    d = inverse_modulaire(e, phi)
    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key

def rsa_chiffrement(message: int, public_key: tuple[int, int]) -> int:
    n, e = public_key
    if not (0 <= message < n):
        raise ValueError("Le message doit être un entier compris entre 0 et n-1.")
    return puissance_modulaire(message, e, n)

def rsa_dechiffrement(ciphertext: int, private_key: tuple[int, int]) -> int:
    n, d = private_key
    if not (0 <= ciphertext < n):
        raise ValueError("Le texte chiffré doit être un entier compris entre 0 et n-1.")
    return puissance_modulaire(ciphertext, d, n)

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')
  
def int_to_bytes(value: int, length: int) -> bytes:
  if value < 0:
    raise ValueError("La valeur doit être un entier non négatif.")
  if length is None:
    length = max(1, (value.bit_length() + 7) // 8)
  return value.to_bytes(length, byteorder='big')

def modulo(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("Le module doit être un entier positif.")
    return a % n

def parametres_rsa(p: int, q: int) -> tuple[int, int]:
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Les nombres p et q doivent être des nombres premiers.")
    if p == q:
        raise ValueError("Les nombres p et q doivent être distincts.")
    n = p * q
    phi = (p - 1) * (q - 1)
    return n, phi

def e_valide(e: int, phi: int) -> bool:
    if e <= 1 or e >= phi:
        return False
    return pgcd(e, phi) == 1

def choisir_e(phi: int) -> int:
    for e in range(3, phi):
        if e_valide(e, phi):
            return e
    raise ValueError("Impossible de trouver un exposant e valide pour φ(n).")

def mod_pow_trace(base: int, exposant: int, mod: int) -> int:
    resultat = 1
    base = base % mod
    print(f"  {'resultat':>9} {'base':>6} {'exposant':>9}")
    print(f"  {resultat:>9} {base:>6} {exposant:>9}   (initial)")

    while exposant > 0:
        if exposant % 2 == 1:
            resultat = (resultat * base) % mod
        base = (base * base) % mod
        exposant //= 2
        print(f"  {resultat:>9} {base:>6} {exposant:>9}")
    return resultat

def empreinte_message(message: str, n: int) -> int:
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    return int.from_bytes(digest, byteorder='big') % n

def signer_rsa(H: int, private_key: tuple[int, int]) -> int:
    n, d = private_key
    if not (0 <= H < n):
        raise ValueError("L'empreinte H doit être un entier compris entre 0 et n-1.")
    return puissance_modulaire(H, d, n)

def verifier_rsa(H: int, S: int, cle_publique: tuple[int, int]) -> bool:
    n, e = cle_publique
    if not (0 <= S < n):
        raise ValueError("la signature doit verifier 0 <= S < n")
    H2 = puissance_modulaire(S, e, n)
    return H2 == H