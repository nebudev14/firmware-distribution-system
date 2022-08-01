import argparse
from multiprocessing.sharedctypes import Value
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def decrypt_firmware(infile, outfile):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        enc_firmware = fp.read()
        
    # load secret keys from file
    with open('../bootloader/secret_build_output.txt', 'rb') as secrets_file:
        aes_key = secrets_file.read(16)
        priv_key = secrets_file.read(138) 
        pub_key = secrets_file.read(65)
        vkey = secrets_file.read(64)
    
    # pad the vkey to fit all of the data
    vkey *= len(enc_firmware)//len(vkey)
    vkey += vkey[:len(enc_firmware)%len(vkey)]

    # first 16 characters are the tag
    tag = enc_firmware[:16]
    # next 16 characters are the nonce
    nonce = enc_firmware[16:32]

    # rest of the data is the encrypted firmware
    enc_firmware = enc_firmware[32:]

    # setup bootleg vigenere decryption
    decrypted_vigenere_firmware = bytes(a ^ b for a, b in zip(enc_firmware, vkey))

    # Decrypt firmware using AES-GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce)
    try: 
        deciphered_firmware = cipher.decrypt_and_verify(decrypted_vigenere_firmware, tag)
    except (ValueError, KeyError):
        print("Invalid decryption!")
        return
    # get signature from deciphered firmware(first 64 bytes of deciphered firmware)
    signature = deciphered_firmware[:64]
    # deciphered firmware is equal to everything besides signature
    deciphered_firmware = deciphered_firmware[64:]

    ecc_key = ECC.import_key(pub_key, curve_name='p256')
    verifier = DSS.new(ecc_key, 'fips-186-3')

    # hash deciphered firmware
    firmware_blob_hash = SHA256.new(deciphered_firmware)

    # verify signature
    try:
        verifier.verify(firmware_blob_hash, signature)
    except (ValueError, KeyError):
        print("Invalid signature!")
        return
    # get version from deciphered firmware(first two bytes of deciphered firmware)
    version = struct.unpack('<H', deciphered_firmware[:2])[0]
    length_of_firmware = struct.unpack('<H', deciphered_firmware[2:4])[0]
    # get firmware from deciphered firmware(everything besides version and length & firmware release message at the end)
    firmware = deciphered_firmware[4:4 + length_of_firmware]
    # release message is everything past firmware to first null byte
    release_message = deciphered_firmware[4 + length_of_firmware:].split(b'\x00')[0]
    print(f"Version: {version} \nLength: {length_of_firmware} bytes \nRelease message: {release_message}")
    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Decrypt Tool')
    parser.add_argument("--infile", help="Path to the firmware image to decrypt.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    args = parser.parse_args()

    decrypt_firmware(infile=args.infile, outfile=args.outfile)
