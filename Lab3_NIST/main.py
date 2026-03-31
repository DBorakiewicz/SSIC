from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

CHUNK_SIZE = 1024 * 1024 * 4  # 4 MB
INPUT_FILES = ['TRNG_P.bit', 'TRNG_F.bit']

def encrypt_3des(input_file, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    output_file = '3DES_'+input_file
    with open(input_file, 'rb') as in_f, open(output_file, 'wb') as out_f:
        chunk = in_f.read(CHUNK_SIZE)

        while chunk:
            next_chunk = in_f.read(CHUNK_SIZE)

            # ostatni chunk → dodaj padding
            if not next_chunk:
                chunk = pad(chunk, DES3.block_size)

            out_f.write(cipher.encrypt(chunk))
            chunk = next_chunk
    return



def encrypt_aes(input_file, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output_file = 'AES_'+input_file
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        chunk = f_in.read(CHUNK_SIZE)

        while chunk:
            next_chunk = f_in.read(CHUNK_SIZE)

            # ostatni chunk → dodaj padding
            if not next_chunk:
                chunk = pad(chunk, AES.block_size)

            f_out.write(cipher.encrypt(chunk))
            chunk = next_chunk

    return


def main():
    key_3des = get_random_bytes(24)  # 24 bytes for Triple DES
    key_aes = get_random_bytes(32)    # 32 bytes for AES-256

    for input_file in INPUT_FILES:
        encrypt_3des(input_file, key_3des)
        encrypt_aes(input_file, key_aes)


if __name__ == "__main__":
    main()


