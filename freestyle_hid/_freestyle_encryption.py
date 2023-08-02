# SPDX-FileCopyrightText: 2023 The freestyle-hid Authors
#
# SPDX-License-Identifier: Apache-2.0


class SpeckEncrypt:
    def __init__(self, key):
        # Perform key expansion and store the round keys
        self.key = key & ((2**128) - 1)
        self.key_schedule = [self.key & 0xFFFFFFFF]
        key_buf = [(self.key >> (x * 32)) & 0xFFFFFFFF for x in range(1, 4)]
        for x in range(26):
            k = self.encryption_round(key_buf[x], self.key_schedule[x], x)
            key_buf.append(k[0])
            self.key_schedule.append(k[1])

    def encryption_round(self, x, y, k):
        # Perform one encryption round of the speck cipher
        x_shift = ((x << 24) + (x >> 8)) & 0xFFFFFFFF
        x_enc = k ^ ((x_shift + y) & 0xFFFFFFFF)
        y_shift = ((y >> 29) + (y << 3)) & 0xFFFFFFFF
        y_enc = x_enc ^ y_shift

        return x_enc, y_enc

    def decryption_round(self, x, y, k):
        # Perform one decryption round of the speck cipher
        new_y = (((x ^ y) << 29) + ((x ^ y) >> 3)) & 0xFFFFFFFF
        msub = (((x ^ k) - new_y) + 0x100000000) % 0x100000000
        new_x = ((msub >> 24) + (msub << 8)) & 0xFFFFFFFF

        return new_x, new_y

    def encrypt_block(self, plain):
        # Encrypt one 64 bit block
        x = (plain >> 32) & 0xFFFFFFFF
        y = plain & 0xFFFFFFFF

        for k in self.key_schedule:
            x, y = self.encryption_round(x, y, k)

        encrypted = (x << 32) + y

        return encrypted

    def decrypt_block(self, encrypted):
        # Decrypt one 64 bit block
        x = (encrypted >> 32) & 0xFFFFFFFF
        y = encrypted & 0xFFFFFFFF

        for k in reversed(self.key_schedule):
            x, y = self.decryption_round(x, y, k)

        plain = (x << 32) + y

        return plain

    def encrypt(self, iv, plain):
        plain = bytearray(plain)
        input_length = len(plain)
        plain.extend(bytes(b"\x00" * (8 - (input_length % 8))))
        iv = int.from_bytes(
            iv.to_bytes(8, byteorder="big"), byteorder="little", signed=False
        )
        output = bytearray()
        for i in range(len(plain) // 8):
            k = self.encrypt_block(iv)
            slice_start = i * 8
            slice_end = slice_start + 8
            res = k ^ int.from_bytes(
                plain[slice_start:slice_end], byteorder="little", signed=False
            )
            output.extend(int.to_bytes(res, 8, byteorder="little", signed=False))
            iv += 1
        encrypted = output[:input_length]
        return bytes(encrypted)

    def decrypt(self, iv, encrypted):
        return self.encrypt(iv, encrypted)


class SpeckCMAC:
    def __init__(self, key):
        self.cipher = SpeckEncrypt(key)

        k0 = self.cipher.encrypt_block(0)
        k0 = int.from_bytes(
            k0.to_bytes(8, byteorder="big"), byteorder="little", signed=False
        )

        k1 = (k0 << 1) & 0xFFFFFFFFFFFFFFFF
        if k0 >> 63 != 0:
            k1 ^= 0x1B

        k2 = (k1 << 1) & 0xFFFFFFFFFFFFFFFF
        if k1 >> 63 != 0:
            k2 ^= 0x1B

        k1 = int.from_bytes(
            k1.to_bytes(8, byteorder="big"), byteorder="little", signed=False
        )
        k2 = int.from_bytes(
            k2.to_bytes(8, byteorder="big"), byteorder="little", signed=False
        )
        self.k1 = k1
        self.k2 = k2

    def sign(self, data):
        c = 0
        i = 0
        data_len = len(data)

        while i < data_len:
            data_left = data_len - i
            slice_start = i
            slice_end = slice_start + 8
            if data_left == 8:
                block = int.from_bytes(data[slice_start:slice_end], "little") ^ self.k1
            elif data_left < 8:
                slice_end = i + data_left
                block = (
                    int.from_bytes(
                        data[slice_start:slice_end]
                        + b"\x80"
                        + b"\x00" * (7 - data_left),
                        "little",
                    )
                    ^ self.k2
                )
            else:
                block = int.from_bytes(data[slice_start:slice_end], "little")
            c = self.cipher.encrypt_block(c ^ block)
            i += 8

        return c

    def derive(self, label, context):
        data = label + b"\x00" + context + b"\x80\x00"
        d1 = self.sign(b"\x01" + data)
        d2 = self.sign(b"\x02" + data) << 64

        return d1 | d2
