import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import ImageTk, Image
import os
from steganocrypt.crypto_utils import derive_key, encrypt_payload, decrypt_payload, generate_salt
from steganocrypt.stego_utils import embed_stego_data, extract_stego_data

class SteganocryptApp:
    def __init__(self, master):
        self.master = master
        master.title("Steganocrypt")

        # Variables
        self.original_image_path = tk.StringVar()
        self.payload_path = tk.StringVar()
        self.output_image_path = tk.StringVar()
        self.decode_input_image_path = tk.StringVar()
        self.output_payload_path = tk.StringVar()
        self.seed_phrase = tk.StringVar()
        self.seed_phrase_key = tk.StringVar()
        self.decode_seed_phrase_key = tk.StringVar()
        self.encode_key_type = tk.StringVar(value="Seed Phrase")
        self.decode_key_type = tk.StringVar(value="Seed Phrase")
        self.seed_phrase_length = tk.IntVar(value=12)
        self.seed_length_options = ["12", "15", "18", "24"]

        # UI Elements
        self.create_encode_frame()
        self.create_decode_frame()

    def create_encode_frame(self):
        encode_frame = tk.LabelFrame(self.master, text="Encode Information", padx=10, pady=10)
        encode_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Original Image Selection
        tk.Label(encode_frame, text="Original Image:").grid(row=0, column=0, sticky="w")
        tk.Entry(encode_frame, textvariable=self.original_image_path, width=50).grid(row=0, column=1)
        tk.Button(encode_frame, text="Browse", command=self.browse_original_image).grid(row=0, column=2)

        # Payload Selection
        tk.Label(encode_frame, text="Payload File:").grid(row=1, column=0, sticky="w")
        tk.Entry(encode_frame, textvariable=self.payload_path, width=50).grid(row=1, column=1)
        tk.Button(encode_frame, text="Browse", command=lambda: self.browse_payload()).grid(row=1, column=2)

        # Output Image Path
        tk.Label(encode_frame, text="Output Image:").grid(row=2, column=0, sticky="w")
        tk.Entry(encode_frame, textvariable=self.output_image_path, width=50).grid(row=2, column=1)
        tk.Button(encode_frame, text="Browse", command=self.save_output_image_as).grid(row=2, column=2)

        # Seed Phrase/Key for Encoding
        tk.Label(encode_frame, text="Key Type:").grid(row=3, column=0, sticky="w")
        key_type_options = ["Seed Phrase", "Private Key"]
        self.encode_key_type_option_menu = tk.OptionMenu(encode_frame, self.encode_key_type, *key_type_options, command=self.update_encode_key_type_ui)
        self.encode_key_type_option_menu.grid(row=3, column=1, sticky="w")

        tk.Label(encode_frame, text="Seed Phrase/Key:").grid(row=4, column=0, sticky="w")
        tk.Entry(encode_frame, textvariable=self.seed_phrase_key, width=50, show="*").grid(row=4, column=1)
        
        # Seed Phrase Length widgets
        self.encode_seed_length_label = tk.Label(encode_frame, text="Seed Phrase Length:")
        self.encode_seed_length_label.grid(row=5, column=0, sticky="w")
        self.encode_seed_length_var = tk.StringVar(self.master)
        self.encode_seed_length_var.set("12") # default value
        self.encode_seed_length_option_menu = tk.OptionMenu(encode_frame, self.encode_seed_length_var, *self.seed_length_options)
        self.encode_seed_length_option_menu.grid(row=5, column=1, sticky="w")
        
        # Generate button
        self.encode_generate_button = tk.Button(encode_frame, text="Generate Seed Phrase", command=lambda: self.generate_seed_phrase(self.seed_phrase_key, self.encode_seed_length_var))
        self.encode_generate_button.grid(row=5, column=2)

        # Save Private Key button (initially hidden)
        self.save_private_key_button = tk.Button(encode_frame, text="Save Private Key", command=self.save_private_key)
        # self.save_private_key_button.grid(row=5, column=3) # Initially hidden

        # Save Seed Phrase button (initially hidden)
        self.save_seed_phrase_button = tk.Button(encode_frame, text="Save Seed Phrase", command=self.save_seed_phrase)
        # self.save_seed_phrase_button.grid(row=5, column=4) # Initially hidden

        # Encode Button
        tk.Button(encode_frame, text="Encode", command=self.encode_data).grid(row=6, column=1, pady=10)

        self.update_encode_key_type_ui() # Set initial UI state

    def create_decode_frame(self):
        decode_frame = tk.LabelFrame(self.master, text="Decode Information", padx=10, pady=10)
        decode_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Input Image for Decoding
        tk.Label(decode_frame, text="Input Image:").grid(row=0, column=0, sticky="w")
        tk.Entry(decode_frame, textvariable=self.decode_input_image_path, width=50).grid(row=0, column=1)
        tk.Button(decode_frame, text="Browse", command=lambda: self.browse_decode_image()).grid(row=0, column=2)

        # Output Payload Path
        tk.Label(decode_frame, text="Output Payload:").grid(row=1, column=0, sticky="w")
        tk.Entry(decode_frame, textvariable=self.output_payload_path, width=50).grid(row=1, column=1)
        tk.Button(decode_frame, text="Browse", command=lambda: self.save_output_payload_as()).grid(row=1, column=2)

        # Seed Phrase/Key for Decoding
        tk.Label(decode_frame, text="Key Type:").grid(row=2, column=0, sticky="w")
        key_type_options = ["Seed Phrase", "Private Key"]
        self.decode_key_type_option_menu = tk.OptionMenu(decode_frame, self.decode_key_type, *key_type_options, command=self.update_decode_key_type_ui)
        self.decode_key_type_option_menu.grid(row=2, column=1, sticky="w")

        tk.Label(decode_frame, text="Seed Phrase/Key:").grid(row=3, column=0, sticky="w")
        tk.Entry(decode_frame, textvariable=self.decode_seed_phrase_key, width=50, show="*").grid(row=3, column=1)
        
        # Seed Phrase Length widgets
        self.decode_seed_length_label = tk.Label(decode_frame, text="Seed Phrase Length:")
        self.decode_seed_length_label.grid(row=4, column=0, sticky="w")
        self.decode_seed_length_var = tk.StringVar(self.master)
        self.decode_seed_length_var.set("12") # default value
        self.decode_seed_length_option_menu = tk.OptionMenu(decode_frame, self.decode_seed_length_var, *self.seed_length_options)
        self.decode_seed_length_option_menu.grid(row=4, column=1, sticky="w")
        
        # Generate button
        # self.decode_generate_button = tk.Button(decode_frame, text="Generate Seed Phrase", command=lambda: self.generate_seed_phrase(self.decode_seed_phrase_key, self.decode_seed_length_var))
        # self.decode_generate_button.grid(row=4, column=2)

        # Save Private Key button (initially hidden)
        # self.decode_save_private_key_button = tk.Button(decode_frame, text="Save Private Key", command=self.save_private_key)
        # self.decode_save_private_key_button.grid(row=4, column=3) # Use a new column for this button

        # Save Seed Phrase button (initially hidden)
        # self.decode_save_seed_phrase_button = tk.Button(decode_frame, text="Save Seed Phrase", command=self.save_seed_phrase)
        # self.decode_save_seed_phrase_button.grid(row=4, column=4) # Use a new column for this button

        # Decode Button
        tk.Button(decode_frame, text="Decode", command=self.decode_data).grid(row=5, column=1, pady=10)
        
        self.update_decode_key_type_ui() # Set initial UI state

    def create_widgets(self):
        # This method is now a placeholder as frames are created by dedicated methods
        pass

    def browse_original_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Image Files", "*.png;*.jpg;*.jpeg;*.bmp"), ("PNG files", "*.png"), ("JPEG files", "*.jpg;*.jpeg"), ("BMP files", "*.bmp")])
        if file_path:
            self.original_image_path.set(file_path)
            self.output_image_path.set(os.path.splitext(file_path)[0] + "_stego.png")

    def save_output_image_as(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg;*.jpeg"), ("BMP files", "*.bmp")])
        if file_path:
            self.output_image_path.set(file_path)

    def browse_decode_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Image Files", "*.png;*.jpg;*.jpeg;*.bmp"), ("PNG files", "*.png"), ("JPEG files", "*.jpg;*.jpeg"), ("BMP files", "*.bmp")])
        if file_path:
            self.decode_input_image_path.set(file_path)
            base_name = os.path.splitext(file_path)[0]
            self.output_payload_path.set(base_name + "_decoded.bin")

    def save_output_payload_as(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("All files", "*.*")])
        if file_path:
            self.output_payload_path.set(file_path)

    def browse_payload(self):
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if file_path:
            self.payload_path.set(file_path)

    def encode_data(self):
        original_image_path = self.original_image_path.get()
        payload_path = self.payload_path.get()
        output_image_path = self.output_image_path.get()
        key_type = self.encode_key_type.get()
        key_value = self.seed_phrase_key.get()

        if not all([original_image_path, payload_path, output_image_path, key_value]):
            messagebox.showerror("Error", "All fields are required for encoding.")
            return

        try:
            with open(payload_path, 'rb') as f:
                payload_data = f.read()

            if key_type == "Seed Phrase":
                words = key_value.split()
                if len(words) not in [12, 15, 18, 24]:
                    messagebox.showerror("Error", "Seed phrase must be 12, 15, 18, or 24 words long.")
                    return
                salt = generate_salt()
                key = derive_key(key_value, salt)
            else:  # Private Key
                salt = generate_salt()
                key = derive_key(key_value, salt)

            nonce, encrypted_payload, tag = encrypt_payload(key, payload_data)

            embed_stego_data(original_image_path, output_image_path, nonce, encrypted_payload, tag, salt)
            messagebox.showinfo("Success", f"Data successfully embedded into {output_image_path}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def decode_data(self):
        decode_input_image_path = self.decode_input_image_path.get()
        output_payload_path = self.output_payload_path.get()
        key_type = self.decode_key_type.get()
        key_value = self.decode_seed_phrase_key.get()

        if not all([decode_input_image_path, key_value]):
            messagebox.showerror("Error", "Input image and key are required for decoding.")
            return

        if not output_payload_path:
            base_name = os.path.splitext(decode_input_image_path)[0]
            output_payload_path = base_name + "_decoded.bin"
            self.output_payload_path.set(output_payload_path)

        try:
            nonce, encrypted_payload, tag, salt = extract_stego_data(decode_input_image_path)

            if key_type == "Seed Phrase":
                words = key_value.split()
                if len(words) not in [12, 15, 18, 24]:
                    messagebox.showerror("Error", "Seed phrase must be 12, 15, 18, or 24 words long.")
                    return
                key = derive_key(key_value, salt)
            else:  # Private Key
                key = derive_key(key_value, salt)

            decrypted_payload = decrypt_payload(key, nonce, encrypted_payload, tag)

            with open(output_payload_path, 'wb') as f:
                f.write(decrypted_payload)

            messagebox.showinfo("Success", f"Data successfully extracted to {output_payload_path}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def update_encode_key_type_ui(self, *args):
        key_type = self.encode_key_type.get()
        if key_type == "Seed Phrase":
            self.encode_seed_length_label.grid(row=5, column=0, sticky="w")
            self.encode_seed_length_option_menu.grid(row=5, column=1, sticky="w")
            self.encode_generate_button.config(text="Generate Seed Phrase", command=lambda: self.generate_seed_phrase(self.seed_phrase_key, self.encode_seed_length_var))
            self.save_private_key_button.grid_forget() # Hide save button
            self.save_seed_phrase_button.grid(row=5, column=4) # Show save seed phrase button
        else: # Private Key
            self.encode_seed_length_label.grid_forget() # Hide label
            self.encode_seed_length_option_menu.grid_forget() # Hide option menu
            self.encode_generate_button.config(text="Generate Private Key", command=lambda: self.generate_private_key(self.seed_phrase_key))
            self.save_private_key_button.grid(row=5, column=3) # Show save button
            self.save_seed_phrase_button.grid_forget() # Hide save seed phrase button

    def update_decode_key_type_ui(self, *args):
        key_type = self.decode_key_type.get()
        if key_type == "Seed Phrase":
            self.decode_seed_length_label.grid(row=4, column=0, sticky="w")
            self.decode_seed_length_option_menu.grid(row=4, column=1, sticky="w")
        else: # Private Key
            self.decode_seed_length_label.grid_forget() # Hide label
            self.decode_seed_length_option_menu.grid_forget() # Hide option menu
            # self.decode_generate_button.config(text="Generate Private Key", command=lambda: self.generate_private_key(self.decode_seed_phrase_key))
            # self.decode_save_private_key_button.grid(row=4, column=3) # Show save button
            # self.decode_save_seed_phrase_button.grid_forget() # Hide save seed phrase button

    def generate_private_key(self, target_key_var):
        # Placeholder for private key generation logic
        # For now, let's just generate a random string as a private key
        import secrets
        private_key = secrets.token_hex(32) # Generate a 32-byte (64-char hex) random key
        target_key_var.set(private_key)
        messagebox.showinfo("Private Key Generated", "A new private key has been generated.")

    def save_private_key(self):
        private_key = self.seed_phrase_key.get()
        if not private_key:
            messagebox.showerror("Error", "No private key to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(private_key)
                messagebox.showinfo("Success", f"Private key saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save private key: {e}")

    def save_seed_phrase(self):
        seed_phrase = self.seed_phrase_key.get()
        if not seed_phrase:
            messagebox.showerror("Error", "No seed phrase to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(seed_phrase)
                messagebox.showinfo("Success", f"Seed phrase saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save seed phrase: {e}")

    def generate_seed_phrase(self, target_seed_phrase_var, seed_length_var):
        try:
            from mnemonic import Mnemonic
            mnemo = Mnemonic("english")
            strength = int(seed_length_var.get()) * 10 # 12 words = 128 bits, 24 words = 256 bits
            if strength not in [120, 150, 180, 240]: # Adjust strength based on word count
                raise ValueError("Invalid seed phrase length selected.")
            
            # BIP-39 strength is in bits, 12 words = 128 bits, 24 words = 256 bits
            # The mnemonic library expects strength in bits, which is word_count * 10 for 12, 15, 18, 21, 24 words respectively.
            # Let's map the word count to the correct strength in bits.
            strength_map = {"12": 128, "15": 160, "18": 192, "24": 256}
            actual_strength = strength_map[seed_length_var.get()]

            words = mnemo.generate(strength=actual_strength)
            target_seed_phrase_var.set(words) # Set the generated seed phrase to the target key field
            print(f"Generated Seed Phrase: {words}") # Debug print statement
            messagebox.showinfo("Seed Phrase Generated", "Please write down your seed phrase: " + words)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate seed phrase: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("800x600")
    app = SteganocryptApp(root)
    root.mainloop()