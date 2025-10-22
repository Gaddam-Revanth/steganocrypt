from PIL import Image

LSB_BITS = 1 # Number of least significant bits to use for embedding

def get_pixel_data(image: Image.Image) -> list[tuple[int, ...]]:
    """
    Extracts all pixel data as a list of tuples (R, G, B, A).
    """
    return list(image.getdata())

def set_pixel_data(image: Image.Image, pixel_data: list[tuple[int, ...]]):
    """
    Sets the pixel data back into the image.
    """
    image.putdata(pixel_data)

def embed_data_into_pixels(pixel_data: list[tuple[int, ...]], data: bytes) -> list[tuple[int, ...]]:
    """
    Embeds data into the least significant bits of pixel data.
    """
    data_bits = ''.join(format(byte, '08b') for byte in data)
    
    # Calculate total available bits in the image
    total_pixel_channels = len(pixel_data) * len(pixel_data[0]) if pixel_data else 0
    max_capacity_bits = total_pixel_channels * LSB_BITS

    if len(data_bits) > max_capacity_bits:
        raise ValueError("Image capacity exceeded.")

    new_pixel_data = [list(p) for p in pixel_data] # Convert tuples to lists for mutability
    data_bit_index = 0

    for i in range(len(new_pixel_data)):
        for j in range(len(new_pixel_data[i])):
            if data_bit_index < len(data_bits):
                original_channel_value = new_pixel_data[i][j]
                # Clear the LSBs
                cleared_channel_value = original_channel_value & (~((1 << LSB_BITS) - 1))
                # Set the new LSBs
                new_pixel_data[i][j] = cleared_channel_value | int(data_bits[data_bit_index], 2)
                data_bit_index += 1
            else:
                break
        if data_bit_index >= len(data_bits):
            break

    return [tuple(p) for p in new_pixel_data] # Convert back to tuples

def extract_data_from_pixels(pixel_data: list[tuple[int, ...]], num_bytes: int) -> bytes:
    """
    Extracts data from the least significant bits of pixel data.
    """
    extracted_bits = []
    total_bits_to_extract = num_bytes * 8
    
    for i in range(len(pixel_data)):
        for j in range(len(pixel_data[i])):
            if len(extracted_bits) < total_bits_to_extract:
                channel_value = pixel_data[i][j]
                extracted_bits.append(str(channel_value & ((1 << LSB_BITS) - 1)))
            else:
                break
        if len(extracted_bits) >= total_bits_to_extract:
            break

    extracted_data_bits = ''.join(extracted_bits)
    
    if len(extracted_data_bits) < total_bits_to_extract:
        raise ValueError("Not enough hidden data found in the image.")

    extracted_bytes = bytearray()
    for i in range(0, total_bits_to_extract, 8):
        extracted_bytes.append(int(extracted_data_bits[i:i+8], 2))

    return bytes(extracted_bytes)

def embed_stego_data(image_path: str, output_path: str, nonce: bytes, ciphertext: bytes, tag: bytes, salt: bytes):
    """
    Embeds encrypted data (nonce, ciphertext, tag, salt) into a PNG image using LSB steganography.
    """
    img = Image.open(image_path).convert("RGBA")
    pixel_data = get_pixel_data(img)

    # Combine all data components with their lengths as prefixes
    data_parts = [nonce, ciphertext, tag, salt]
    full_data_to_embed = b''
    for part in data_parts:
        full_data_to_embed += len(part).to_bytes(4, 'big') + part

    # Calculate maximum capacity
    total_pixel_channels = len(pixel_data) * len(pixel_data[0]) if pixel_data else 0
    max_capacity_bytes = (total_pixel_channels * LSB_BITS) // 8

    # We need to embed the length of the data + the data itself
    if len(full_data_to_embed) + 4 > max_capacity_bytes: # +4 for the overall length prefix
        raise ValueError(f"Combined data size ({len(full_data_to_embed)} bytes) exceeds image capacity ({max_capacity_bytes} bytes).")

    # Prepend the total length of the combined data
    full_data_to_embed = len(full_data_to_embed).to_bytes(4, 'big') + full_data_to_embed

    final_pixel_data = embed_data_into_pixels(pixel_data, full_data_to_embed)

    new_img = Image.new(img.mode, img.size)
    set_pixel_data(new_img, final_pixel_data)
    new_img.save(output_path)

def extract_stego_data(image_path: str) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Extracts hidden data (nonce, ciphertext, tag, salt) from a stego PNG image.
    """
    img = Image.open(image_path).convert("RGBA")
    pixel_data = get_pixel_data(img)

    flat_channel_data = []
    for pixel in pixel_data:
        flat_channel_data.extend(pixel)

    # Helper to extract a specific number of bytes from the bit stream
    def _extract_bytes_from_bits(start_bit_index, num_bytes_to_extract):
        bits = []
        total_bits = num_bytes_to_extract * 8
        for i in range(total_bits):
            current_bit_index = start_bit_index + i
            channel_index = current_bit_index // LSB_BITS
            bit_in_channel_index = current_bit_index % LSB_BITS

            if channel_index >= len(flat_channel_data):
                raise ValueError("Not enough hidden data found in the image.")

            channel_value = flat_channel_data[channel_index]
            bits.append(str((channel_value >> bit_in_channel_index) & 1))
        
        extracted_data_bits = ''.join(bits)
        extracted_bytes = bytearray()
        for j in range(0, total_bits, 8):
            extracted_bytes.append(int(extracted_data_bits[j:j+8], 2))
        return bytes(extracted_bytes), start_bit_index + total_bits

    current_bit_index = 0

    # Extract overall data length (4 bytes)
    overall_data_length_bytes, current_bit_index = _extract_bytes_from_bits(current_bit_index, 4)
    overall_data_length = int.from_bytes(overall_data_length_bytes, 'big')

    # Extract nonce length (4 bytes)
    nonce_length_bytes, current_bit_index = _extract_bytes_from_bits(current_bit_index, 4)
    nonce_length = int.from_bytes(nonce_length_bytes, 'big')
    # Extract nonce
    nonce, current_bit_index = _extract_bytes_from_bits(current_bit_index, nonce_length)

    # Extract ciphertext length (4 bytes)
    ciphertext_length_bytes, current_bit_index = _extract_bytes_from_bits(current_bit_index, 4)
    ciphertext_length = int.from_bytes(ciphertext_length_bytes, 'big')
    # Extract ciphertext
    ciphertext, current_bit_index = _extract_bytes_from_bits(current_bit_index, ciphertext_length)

    # Extract tag length (4 bytes)
    tag_length_bytes, current_bit_index = _extract_bytes_from_bits(current_bit_index, 4)
    tag_length = int.from_bytes(tag_length_bytes, 'big')
    # Extract tag
    tag, current_bit_index = _extract_bytes_from_bits(current_bit_index, tag_length)

    # Extract salt length (4 bytes)
    salt_length_bytes, current_bit_index = _extract_bytes_from_bits(current_bit_index, 4)
    salt_length = int.from_bytes(salt_length_bytes, 'big')
    # Extract salt
    salt, current_bit_index = _extract_bytes_from_bits(current_bit_index, salt_length)

    return nonce, ciphertext, tag, salt