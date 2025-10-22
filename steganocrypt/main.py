import argparse
import os
from Cryptodome.Random import get_random_bytes

from crypto_utils import derive_key, encrypt_payload, decrypt_payload, generate_salt, NONCE_SIZE, SALT_SIZE
from stego_utils import embed_stego_data, extract_stego_data

def encode(args):
    """
    Encodes a payload into an image using steganography and cryptography.
    """
    try:
        with open(args.payload, 'rb') as f:
            payload_data = f.read()

        salt = generate_salt()
        key = derive_key(args.seed, salt)
        nonce, ciphertext, tag = encrypt_payload(key, payload_data)

        # Combine salt, nonce, ciphertext, and tag for embedding
        # The order is important for extraction
        data_to_embed = salt + nonce + ciphertext + tag

        embed_stego_data(args.input, args.output, data_to_embed)
        print(f"Payload successfully encoded into {args.output}")

    except ValueError as e:
        print(f"Error during encoding: {e}")
    except FileNotFoundError:
        print(f"Error: Input file not found. Please check the path for {args.input} or {args.payload}.")
    except Exception as e:
        print(f"An unexpected error occurred during encoding: {e}")

def decode(args):
    """
    Decodes a hidden payload from an image using steganography and cryptography.
    """
    try:
        extracted_data = extract_stego_data(args.input)

        # Extract salt, nonce, ciphertext, and tag based on their sizes
        extracted_salt = extracted_data[:SALT_SIZE]
        extracted_nonce = extracted_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        extracted_ciphertext = extracted_data[SALT_SIZE + NONCE_SIZE : -16] # Tag is 16 bytes
        extracted_tag = extracted_data[-16:]

        key = derive_key(args.seed, extracted_salt)
        decrypted_payload = decrypt_payload(key, extracted_nonce, extracted_ciphertext, extracted_tag)

        output_filename = args.output if args.output else "decoded_payload.bin"
        with open(output_filename, 'wb') as f:
            f.write(decrypted_payload)
        print(f"Payload successfully decoded and saved to {output_filename}")

    except ValueError as e:
        print(f"Error during decoding: {e}")
    except FileNotFoundError:
        print(f"Error: Input image file not found. Please check the path for {args.input}.")
    except Exception as e:
        print(f"An unexpected error occurred during decoding: {e}")

def main():
    parser = argparse.ArgumentParser(description="Steganography and Cryptography Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Encode command
    encode_parser = subparsers.add_parser('encode', help="Encode a payload into an image")
    encode_parser.add_argument('--input', '-i', required=True, help="Input cover PNG image path")
    encode_parser.add_argument('--output', '-o', required=True, help="Output stego PNG image path")
    encode_parser.add_argument('--payload', '-p', required=True, help="Path to the payload file (text or any file)")
    encode_parser.add_argument('--seed', '-s', required=True, help="BIP-39 seed phrase or private key")
    encode_parser.set_defaults(func=encode)

    # Decode command
    decode_parser = subparsers.add_parser('decode', help="Decode a payload from an image")
    decode_parser.add_argument('--input', '-i', required=True, help="Input stego PNG image path")
    decode_parser.add_argument('--seed', '-s', required=True, help="BIP-39 seed phrase or private key")
    decode_parser.add_argument('--output', '-o', help="Output file path for the decoded payload (defaults to decoded_payload.bin)")
    decode_parser.set_defaults(func=decode)

    args = parser.parse_args()

    if args.command:
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()