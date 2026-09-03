# -*- coding: utf-8 -*-
"""Kryptering av kartverktygets datafiler.

Två nivåer, så att lösenordet går att byta utan att röra datafilerna:

  huvudnyckel   32 slumpade byte som krypterar själva datafilerna. Byts sällan.
  lösenord      krypterar huvudnyckeln. Resultatet ligger i nyckel.json. Byts när
                som helst, av arbetsflödet i .github/workflows, utan att någon
                datafil behöver skrivas om.

Format på en krypterad datafil:  iv (12 byte) | ciphertext
Format i nyckel.json:            salt, iv och den inpackade huvudnyckeln, base64

Användning:

    python kryptera.py nyckel                       skriver ut en ny huvudnyckel
    python kryptera.py fil IN UT --nyckel NYCKEL    krypterar en fil
    python kryptera.py nyckelfil UT --nyckel NYCKEL --losen LOSEN
    python kryptera.py allt KLARTEXTMAPP --ut SAJTMAPP --nyckel NYCKEL --losen LOSEN
"""
import argparse, base64, hashlib, json, os, secrets, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 250000
# Filerna som göms bakom lösenordet. Geometrin räknas hit eftersom klusterindelningen
# är själva modellen; logotyp och vendor-koden är öppna och lämnas som de är.
FILER = ['klusterdata.json', 'rostdata.csv', 'geo_kluster.topojson', 'geo_kommun.topojson',
         'lokaler_2022.geojson', 'lokaler_2026.geojson', 'valdeltagande_2022.json',
         'valdeltagande_2022.png']

b64 = lambda b: base64.b64encode(b).decode()
avb64 = lambda s: base64.b64decode(s)


def kryptera(data: bytes, nyckel: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + AESGCM(nyckel).encrypt(iv, data, None)


def packa_nyckel(nyckel: bytes, losen: str) -> dict:
    salt = os.urandom(16)
    iv = os.urandom(12)
    kek = hashlib.pbkdf2_hmac('sha256', losen.encode(), salt, ITER, 32)
    return {'iter': ITER, 'salt': b64(salt), 'iv': b64(iv),
            'nyckel': b64(AESGCM(kek).encrypt(iv, nyckel, None))}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('kommando', choices=['nyckel', 'fil', 'nyckelfil', 'allt'])
    p.add_argument('args', nargs='*')
    p.add_argument('--nyckel', dest='hn', help='huvudnyckel i base64')
    p.add_argument('--losen', help='lösenordet användarna skriver')
    p.add_argument('--ut', help='mapp att skriva .enc-filerna till (allt)')
    a = p.parse_args()

    if a.kommando == 'nyckel':
        print(b64(secrets.token_bytes(32)))
        return

    if not a.hn:
        sys.exit('--nyckel saknas')
    hn = avb64(a.hn)
    if len(hn) != 32:
        sys.exit('huvudnyckeln måste vara 32 byte i base64')

    if a.kommando == 'fil':
        if len(a.args) != 2:
            sys.exit('ange IN och UT')
        src, dst = a.args
        open(dst, 'wb').write(kryptera(open(src, 'rb').read(), hn))
        print(f'{dst}  {os.path.getsize(dst)/1e6:.2f} MB')

    elif a.kommando == 'nyckelfil':
        if len(a.args) != 1 or not a.losen:
            sys.exit('ange UT samt --losen')
        json.dump(packa_nyckel(hn, a.losen), open(a.args[0], 'w'))
        print(f'{a.args[0]} skriven')

    elif a.kommando == 'allt':
        if len(a.args) != 1 or not a.losen:
            sys.exit('ange MAPP samt --losen')
        mapp = a.args[0]
        ut = a.ut or mapp
        os.makedirs(ut, exist_ok=True)
        for f in FILER:
            src = os.path.join(mapp, f)
            if not os.path.exists(src):
                print(f'  hoppar över {f}, finns inte')
                continue
            dst = os.path.join(ut, f + '.enc')
            open(dst, 'wb').write(kryptera(open(src, 'rb').read(), hn))
            print(f'  {f}.enc  {os.path.getsize(dst)/1e6:.2f} MB')
        json.dump(packa_nyckel(hn, a.losen), open(os.path.join(ut, 'nyckel.json'), 'w'))
        print('  nyckel.json skriven')


if __name__ == '__main__':
    main()
