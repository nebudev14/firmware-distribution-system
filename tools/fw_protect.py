"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        
    # load secret keys from file
    with open('secret_build_output.txt', 'rb') as secrets_file:
        aes_key = secrets_file.read(16)
        priv_key = secrets_file.read(48) 
        pub_key = secrets_file.read(44)
        vkey = secrets_file.read(64)

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message

    # sign
    ecc_key = ECC.import_key(priv_key)
    signer = eddsa.new(ecc_key, 'rfc8032')
    signed_firmware = firmware_blob + signer.sign(firmware_blob)
    
    
    # Create cipher object
    cipher = AES.new(aes_key, AES.MODE_GCM)
    # assert that version is an integer
    cipher.update(version)
    

    nonce = cipher.nonce
    
    encrypted_firmware_blob, tag = cipher.encrypt_and_digest(signed_firmware)
    
    output = encrypted_firmware_blob + tag + nonce
    
    # vigenere cipher
    
    # pad the vkey to fit all of the data
    vkey *= len(output)//len(vkey)
    vkey += vkey[:len(output)%len(vkey)]
    
    output = bytes(a ^ b for a, b in zip(output, vkey))
    
    # null terminate
    output += b'\00'
    
    # pad output
    output += Crypto.Random.get_random_bytes(64 - len(output)%64)
    
    
    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
