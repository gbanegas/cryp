
class hc128:
    KEY_SIZE = 32

    def __init__(self):
        self.P = []
        self.Q = []
        self.W = []
        self.count = 0
        self.current_stream = 0
        self.current_in_stream = 0


    def set_key(self, key):
        """
        " Set the key for this stream cipher. <TT>key</TT> must be an array of
        " bytes whose length is equal to <TT>keySize()</TT>. If the stream cipher
        " includes both a key and a nonce, <TT>key</TT> contains the bytes of the
        " key followed by the bytes of the nonce. The keystream generator is
        " initialized, such that successive calls to <TT>encrypt()</TT> will
        " encrypt or decrypt a series of bytes.
        "
        " @param key Key.
        """

        """Initiailization Step 1: Fill W table with key, IV and generated values"""
        for i in range(0, 4):
            temp = key[4 * i]
            for shift in range(1, 4):
                temp ^= key[4 * i + shift] << (8 * shift)
                # temp = temp << 8 ^ key[4 * i + shift]
            self.W.insert(i, temp)
            self.W.insert(i + 4, temp)
        for i in range(4, 8):
            temp = key[4 * i]
            for shift in range(1, 4):
                temp ^= key[4 * i + shift] << (8 * shift)
                # temp = temp << 8 ^ key[4 * i + shift]
            self.W.insert(i + 4, temp)
            self.W.insert(i + 8, temp)
        for i in range(16, 1280):
            f2 = ((self.W[i - 2] >> 17) ^ (self.W[i - 2] << (32 - 17))) ^ (
                (self.W[i - 2] >> 19) ^ (self.W[i - 2] << (32 - 19))) ^ (self.W[i - 2] >> 10)
            f1 = ((self.W[i - 15] >> 7) ^ (self.W[i - 15] << (32 - 7))) ^ (
                (self.W[i - 15] >> 18) ^ (self.W[i - 15] << (32 - 18))) ^ (self.W[i - 15] >> 3)
            self.W.insert(i, (f2 + f1 + self.W[i - 7] + self.W[i - 16] + i) % (2 ** 32))

        """Initiailization Step 2: Starting at element 256, copy 512 elements to P and other 512 to Q"""
        for i in range(0, 512):
            self.P.insert(i, self.W[i + 256])
        for i in range(0, 512):
            self.Q.insert(i, self.W[i + 768])

        """Initiailization Step 3: Run cipher 1024 steps"""
        for i in range(0, 512):
            g1 = ((((self.P[(i - 3)] >> 10) ^ (self.P[(i - 3)] << (32 - 10))) ^ (
                (self.P[(i - 511)] >> 23) ^ (self.P[(i - 511)] << (32 - 23)))) + (
                      (self.P[(i - 10)] >> 8) ^ (self.P[(i - 10)] << (32 - 8)))) % 2 ** 32
            pTemp = [self.P[(i - 12)] >> shift & 0xff for shift in (24, 16, 8, 0)]
            h1 = (self.Q[pTemp[3]] + self.Q[(pTemp[1] + 256)]) % 2 ** 32
            self.P[i] = ((self.P[i] + g1) % 2 ** 32) ^ h1
        for i in range(0, 512):
            g2 = ((((self.Q[(i - 3)] << 10) ^ (self.Q[(i - 3)] >> (32 - 10))) ^ (
                (self.Q[(i - 511)] << 23) ^ (self.Q[(i - 511)] >> (32 - 23)))) + (
                      (self.Q[(i - 10)] << 8) ^ (self.Q[(i - 10)] >> (32 - 8)))) % 2 ** 32
            qTemp = [self.Q[(i - 12)] >> shift & 0xff for shift in (24, 16, 8, 0)]
            h2 = (self.P[qTemp[3]] + self.P[(qTemp[1] + 256)]) % 2 ** 32
            self.Q[i] = ((self.Q[i] + g2) % 2 ** 32) ^ h2


    def init_keystream(self):
        i = self.count % 512
        if self.count % 1024 < 512:
            g1 = ((((self.P[(i - 3)] >> 10) ^ (self.P[(i - 3)] << (32 - 10))) ^ ((self.P[(i - 511)] >> 23) ^ (self.P[(i - 511)] << (32 - 23)))) + ((self.P[(i - 10)] >> 8) ^ (self.P[(i - 10)] << (32 - 8)))) % (2 ** 32)
            self.P[i] = ((self.P[i] + g1) % 2 ** 32)
            p_temp = [self.P[(i - 12)] >> shift & 0xff for shift in (24, 16, 8, 0)]
            h1 = (self.Q[p_temp[3]] + self.Q[(p_temp[1] + 256)]) % (2 ** 32)
            self.current_stream = h1 ^ self.P[i]
            self.current_in_stream = 4
        else:
            g2 = ((((self.Q[(i - 3)] << 10) ^ (self.Q[(i - 3)] >> (32 - 10))) ^ (
                (self.Q[(i - 511)] << 23) ^ (self.Q[(i - 511)] >> (32 - 23)))) + (
                      (self.Q[(i - 10)] << 8) ^ (self.Q[(i - 10)] >> (32 - 8)))) % (2 ** 32)
            self.Q[i] = ((self.Q[i] + g2) % 2 ** 32)
            qTemp = [self.Q[(i - 12)] >> shift & 0xff for shift in (24, 16, 8, 0)]
            h2 = (self.P[qTemp[3]] + self.P[(qTemp[1] + 256)]) % (2 ** 32)
            self.current_stream = h2 ^ self.Q[i]
            self.current_in_stream = 4
        self.count += 1

    def crypt(self, b):
        """
        " Encrypt or decrypt the given byte. Only the least significant 8 bits of
        " <TT>b</TT> are used. If <TT>b</TT> is a plaintext byte, the ciphertext
        " byte is returned as a value from 0 to 255. If <TT>b</TT> is a ciphertext
        " byte, the plaintext byte is returned as a value from 0 to 255.
        "
        " @param b Plaintext byte (if encrypting), ciphertext byte (if
        " decrypting).
        "
        " @return Ciphertext byte (if encrypting), plaintext byte (if decrypting).
        """

        """If no keystream currently generated, generate 32-bits"""
        if self.current_in_stream == 0:
            self.init_keystream()

        """Once there is keystream, encrypt the byte and remove used keystream from queue"""
        temp = (self.current_stream >> (8 * (4 - self.current_in_stream))) & 0x000000ff

        self.current_in_stream -= 1
        return temp ^ b

hc = hc128()
print hc.crypt(b'abc')
