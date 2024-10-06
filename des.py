# Tugas Data Encryption Standard
# Arkan Arsalan Amanullah (5025221129)

import re

# Initial Permutation Table (64)
init_perm_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Expansion D-box Table (56)
exp_dbox_table = [
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
]

# 32 bits Permutation Table (32)
perm_32_bits_table = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# S-box Table (64)
sbox_table = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Final Permutation Table (64)
fin_perm_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Parity bit drop table (Discard 8th bit of the initial key)
key_par_drop = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Shift table
shift_table = [
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
]

# Key Compression Table for compressing 56 bits to 48 bits
key_comp_table = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]


# Convert hexadecimal to binary
def hex_to_bin(hex):
    hex_bin_map = {
        '0': "0000", '1': "0001", '2': "0010", '3': "0011",
        '4': "0100", '5': "0101", '6': "0110", '7': "0111",
        '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
        'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"
    }
    
    binary_output = ""
    for i in range(len(hex)):
        binary_output = binary_output + hex_bin_map[hex[i]]
    return binary_output


# Convert binary to hexadecimal
def bin_to_hex(bin):
    bin_hex_map = {
        "0000": '0', "0001": '1', "0010": '2', "0011": '3',
        "0100": '4', "0101": '5', "0110": '6', "0111": '7',
        "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
        "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'
    }
    
    hex = ""
    for i in range(0, len(bin), 4):
        bin_digits = str(bin[i]) + str(bin[i + 1]) + str(bin[i + 2]) + str(bin[i + 3])
        hex = hex + bin_hex_map[bin_digits]
    return hex


# Convert binary to decimal
def bin_to_dec(bin):
    return int(str(bin), 2)


# Convert decimal to binary
def dec_to_bin(dec):
    bin_output = bin(dec).replace("0b", "")
    
    # Add zero in the front if digits less than multiple of 4
    if (len(bin_output) % 4 != 0):
        div = int(len(bin_output) / 4)
        zero_needed = (4 * (div + 1)) - len(bin_output)
        for _ in range(0, zero_needed):
            bin_output = '0' + bin_output
            
    return bin_output


# Permutation
def permute(input_bits, permutation_indices, num_bits):
    permutation = ""
    for i in range(0, num_bits):
        permutation = permutation + input_bits[permutation_indices[i] - 1]
        
    return permutation


# Shifting left for given bits
def shift_left(input_bits, n_shifts):
    temp_str = ""
    for _ in range(n_shifts):
        for j in range(1, len(input_bits)):
            temp_str = temp_str + input_bits[j]
            
        temp_str = temp_str + input_bits[0]
        output_bits = temp_str
        temp_str = ""
        
    return output_bits


# XOR function
def xor(bin1, bin2):
    xor_output = ""
    for i in range(len(bin1)):
        if bin1[i] == bin2[i]:
            xor_output = xor_output + "0"
        else:
            xor_output = xor_output + "1"
    return xor_output


# Encrypt plain text
def encrypt(plain_text, round_keys):
    # Convert plaint text to binary
    plain_text = hex_to_bin(plain_text)

    # Initial Permutation
    plain_text = permute(plain_text, init_perm_table, 64)
    
    print(f"{'Round Count':<12} | {'Left Half':<17} | {'Right Half':<17} | {'Round Key':<15}")
    print('-' * 83)

    # Splitting 32 bits each for the plain text
    left_half = plain_text[0:32]
    right_half = plain_text[32:64]

    # 16 rounds
    for i in range(0, 16):
        # Expansion D-box for right half from 32 to 48 bits
        right_48 = permute(right_half, exp_dbox_table, 48)

        # XOR right half 48 bits with the current round key
        xor_rh_rk = xor(right_48, round_keys[i])

        # Substitute using sbox (48 to 32 bits)
        sbox_res = ""
        for j in range(0, 8):
            row = bin_to_dec(int(xor_rh_rk[j * 6] + xor_rh_rk[j * 6 + 5]))
            col = bin_to_dec(int(xor_rh_rk[j * 6 + 1] + xor_rh_rk[j * 6 + 2] + xor_rh_rk[j * 6 + 3] + xor_rh_rk[j * 6 + 4]))
            val = sbox_table[j][row][col]
            sbox_res += dec_to_bin(val)

        # permutation (32 bits)
        perm_32_res = permute(sbox_res, perm_32_bits_table, 32)

        # XOR left half with result of permutation to get 32 bits
        result = xor(left_half, perm_32_res)
        left_half = result

        # Swap left half and right half, except last round
        if i != 15:
            left_half, right_half = right_half, left_half

        # Print the result after each round
        round_keys_hex = bin_to_hex(round_keys[i])
        print(f"{i + 1:<12} | {bin_to_hex(left_half):<17} | {bin_to_hex(right_half):<17} | {round_keys_hex:<15}")


    # Combine the left_half and right_half blocks after the final round
    combine = left_half + right_half

    # Final permutation
    cipher_text = permute(combine, fin_perm_table, 64)
    
    return bin_to_hex(cipher_text)


# Decrypt cipher text
def decrypt(cipher_text, round_keys):
    round_keys_reverse = round_keys[::-1]
    plain_text = encrypt(cipher_text, round_keys_reverse)

    return plain_text


# Generate rounds key
def generate_round_key(key):
    # Convert key to binary
    key = hex_to_bin(key)
    
    # Parity bits drop, from 64 to 56 bits
    key = permute(key, key_par_drop, 56)
    
    left_half = key[0:28]
    right_half = key[28:56]
    
    round_keys = []
    
    for i in range(0, 16):
        # Shifting bits
        left_half = shift_left(left_half, shift_table[i])
        right_half = shift_left(right_half, shift_table[i])
        
        # Combine left and right half
        combine_str = left_half + right_half
        
        # Compression of key from 56 to 48 bits
        round_key = permute(combine_str, key_comp_table, 48)
        
        round_keys.append(round_key)
        
    return round_keys


def main():
    # Input for plain text and key
    pattern = re.compile(r'^[0-9A-F]{16}$')

    while True:
        plain_text = input("Input plain text (16 Characters 0-9 or A-F): ").upper()
        if pattern.match(plain_text):
            break
        else:
            print("Error: Plain text must be exactly 16 characters long and consist only of 0-9 or A-F.")

    while True:
        key = input("Input key (16 Characters 0-9 or A-F): ").upper()
        if pattern.match(key):
            break
        else:
            print("Error: Key must be exactly 16 characters long and consist only of 0-9 or A-F.")
    

    # Generate round key
    round_keys = generate_round_key(key)
    
    # Encrypt
    print("\nEncryption")
    cipher_text = encrypt(plain_text, round_keys)
    print("Cipher Text : ", cipher_text)
    
    print()
    
    # Decrypt
    print("Decryption")
    decrypted_plain_text = decrypt(cipher_text, round_keys)
    print("Plain Text : ", decrypted_plain_text)
    
    
if __name__ == "__main__":
    main()