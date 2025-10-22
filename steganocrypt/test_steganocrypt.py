import unittest
import os
from PIL import Image
from Crypto.Random import get_random_bytes
import shutil

from crypto_utils import derive_key, encrypt_payload, decrypt_payload, generate_salt, NONCE_SIZE, SALT_SIZE, STEGO_HEADER
from stego_utils import embed_stego_data, extract_stego_data, LSB_BITS

class TestSteganocrypt(unittest.TestCase):

    def setUp(self):
        self.test_dir = "test_data"
        os.makedirs(self.test_dir, exist_ok=True)
        self.cover_image_path = os.path.join(self.test_dir, "cover.png")
        self.stego_image_path = os.path.join(self.test_dir, "stego.png")
        self.payload_path = os.path.join(self.test_dir, "payload.txt")
        self.decoded_payload_path = os.path.join(self.test_dir, "decoded_payload.txt")

        # Create a dummy cover image
        img = Image.new('RGBA', (100, 100), color = 'red')
        img.save(self.cover_image_path)

        # Create a dummy payload file
        with open(self.payload_path, 'w') as f:
            f.write("This is a secret message.")

        self.seed = "test seed phrase"

    def tearDown(self):
        # Clean up test files
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_end_to_end_encryption_decryption(self):
        # 1. Encode
        with open(self.payload_path, 'rb') as f:
            payload_data = f.read()

        salt = generate_salt()
        key = derive_key(self.seed, salt)
        nonce, ciphertext, tag = encrypt_payload(key, payload_data)
        data_to_embed = salt + nonce + ciphertext + tag

        embed_stego_data(self.cover_image_path, self.stego_image_path, data_to_embed)

        self.assertTrue(os.path.exists(self.stego_image_path))

        # 2. Decode
        extracted_data = extract_stego_data(self.stego_image_path)

        extracted_salt = extracted_data[:SALT_SIZE]
        extracted_nonce = extracted_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        extracted_ciphertext = extracted_data[SALT_SIZE + NONCE_SIZE : -16]
        extracted_tag = extracted_data[-16:]

        decoded_key = derive_key(self.seed, extracted_salt)
        decrypted_payload = decrypt_payload(decoded_key, extracted_nonce, extracted_ciphertext, extracted_tag)

        self.assertEqual(payload_data, decrypted_payload)

    def test_capacity_limits(self):
        # Create a very small image
        small_img_path = os.path.join(self.test_dir, "small_cover.png")
        img = Image.new('RGBA', (1, 1), color = 'blue')
        img.save(small_img_path)

        # Calculate max capacity for a 1x1 RGBA image (4 channels)
        # Each channel can hold LSB_BITS, so 4 * LSB_BITS bits total
        # Plus 4 bytes for data length (32 bits)
        max_capacity_bytes = (4 * LSB_BITS) // 8
        
        # Test with data that exceeds capacity
        large_payload = b'a' * (max_capacity_bytes + 1)
        salt = generate_salt()
        key = derive_key(self.seed, salt)
        nonce, ciphertext, tag = encrypt_payload(key, large_payload)
        data_to_embed = salt + nonce + ciphertext + tag

        with self.assertRaises(ValueError) as cm:
            embed_stego_data(small_img_path, self.stego_image_path, data_to_embed)
        self.assertIn("exceeds image capacity", str(cm.exception))

    def test_wrong_seed_rejection(self):
        # Encode with correct seed
        with open(self.payload_path, 'rb') as f:
            payload_data = f.read()

        salt = generate_salt()
        key = derive_key(self.seed, salt)
        nonce, ciphertext, tag = encrypt_payload(key, payload_data)
        data_to_embed = salt + nonce + ciphertext + tag

        embed_stego_data(self.cover_image_path, self.stego_image_path, data_to_embed)

        # Try to decode with a wrong seed
        wrong_seed = "wrong seed phrase"
        extracted_data = extract_stego_data(self.stego_image_path)

        extracted_salt = extracted_data[:SALT_SIZE]
        extracted_nonce = extracted_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        extracted_ciphertext = extracted_data[SALT_SIZE + NONCE_SIZE : -16]
        extracted_tag = extracted_data[-16:]

        wrong_key = derive_key(wrong_seed, extracted_salt)

        with self.assertRaises(ValueError) as cm:
            decrypt_payload(wrong_key, extracted_nonce, extracted_ciphertext, extracted_tag)
        self.assertIn("Decryption failed", str(cm.exception))

    def test_tampered_stego_header_rejection(self):
        # Encode with correct seed
        with open(self.payload_path, 'rb') as f:
            payload_data = f.read()

        salt = generate_salt()
        key = derive_key(self.seed, salt)
        nonce, ciphertext, tag = encrypt_payload(key, payload_data)
        data_to_embed = salt + nonce + ciphertext + tag

        embed_stego_data(self.cover_image_path, self.stego_image_path, data_to_embed)

        # Manually tamper with the STEGO_HEADER (this is a bit tricky with LSB, but we can simulate it)
        # For simplicity, we'll just modify the first few bytes of the extracted data to simulate tampering
        # In a real scenario, this would involve modifying the LSBs of the image directly.
        extracted_data = extract_stego_data(self.stego_image_path)
        
        # Simulate tampering by changing the first byte of the ciphertext (which includes the header)
        tampered_data = bytearray(extracted_data)
        # Find the start of the ciphertext (which contains the STEGO_HEADER)
        ciphertext_start_index = SALT_SIZE + NONCE_SIZE
        if len(tampered_data) > ciphertext_start_index:
            tampered_data[ciphertext_start_index] = (tampered_data[ciphertext_start_index] + 1) % 256
        
        extracted_salt = tampered_data[:SALT_SIZE]
        extracted_nonce = tampered_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        extracted_ciphertext = tampered_data[SALT_SIZE + NONCE_SIZE : -16]
        extracted_tag = tampered_data[-16:]

        decoded_key = derive_key(self.seed, extracted_salt)

        with self.assertRaises(ValueError) as cm:
            decrypt_payload(decoded_key, extracted_nonce, extracted_ciphertext, extracted_tag)
        self.assertIn("Decryption failed", str(cm.exception))

if __name__ == '__main__':
    unittest.main()