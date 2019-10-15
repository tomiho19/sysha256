# -*- coding: utf-8 -*-

"""
    Символы и операции (Дискретная математика 2 курс)
    ∧ Логическое и, Конъю́нкция
    ∨ Логическое или, Дизъю́нкция
    ⊕ XOR, либо ... либо ... (0 - 0 = 0, 1 - 1 = 1, 1 - 0 = 1).
    ¬ В js и python это ~ (тильда оператор), (0011, 0101 = 0001) складываем биты, когда они равны двум 1 в результате получаем тоже 1
    + Сложение по модулю 2, строгая дизъюнкция, пример для бинарного сложения (0 - 0 = 0, 1 - 0 = 1, 0 - 1 = 1, 1 - 1 = 0)
    << сдвиг битов влево (10101010b << 1 = 01010100b)
    >> сдвиг битов вправо (10101010b >> 1 = 010100b)
"""


BLOCK_SIZE = 64    # Размер внутреннего блока алгоритма хеширования в байтах
DIGEST_SIZE = 32   # Размер уже готового, полученного хеша в байтах
BITS_IN_WORD = 32  # Количество бит в слове :)

# SHA-224 и SHA-256 используют одинаковую последовательность из шестидесяти четырех постоянных 32-разрядных слов
# Эти слова представляют собой первые тридцать два бита дробных частей корней куба первых шестидесяти четырех простых чисел
K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Перед началом вычисления хеша для каждого из алгоритмов защищенного хеша необходимо установить начальное значение хеша,
# Размер и количество слов в H (0) зависит от размера дайджеста сообщения
# Для SHA-256 начальное значение хеша, H (0), должно состоять из следующих восьми 32-битных слов в шестнадцатеричном виде
INITIAL_HASH = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]


def shift_right(x, n):
    """ Возвращает как ни странно число
    Здесь, операция сдвига вправо SHR n (x), где x - это w-битное слово,
    а n - целое число с 0 ≤ n <w, определяется как SHR n (x) = x >> n
    """
    return (x & 0xffffffff) >> n


def rotate_right(x, y):
    """ Возвращает число
    Операция поворота вправо (круговое смещение вправо), где x - это w-битное слово,
    а n - целое число с 0 ≤ n <w, определяется как ROTR n (x) = (x >> n) ∨ (x << w - n)
    """
    return (((x & 0xffffffff) >> (y & 31)) | (x << (BITS_IN_WORD - (y & 31)))) & 0xffffffff


"""
SHA256 использует шесть логических функций, где каждая функция работает с 64-битными словами, которые представлены как x, y и z
Результатом каждой функции является новое 64-битное слово
"""


def choose(x, y, z):
    """Входной параметр x выбирает, будет ли результат из y или z

    Ch(x,y,z)=(x∧y)⊕(¬x∧z)
    """
    return z ^ (x & (y ^ z))


def majority(x, y, z):
    """Результат устанавливается в соответствии с большинством из 3 входных параметров

    Maj(x, y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)

    Функции определены для битовых векторов (32 бита в случае SHA-256)
    """
    return ((x | y) & z) | (x & y)


def sigma0(x):
    # ROTR 2(x) ⊕ ROTR 13(x) ⊕ ROTR 22(x)
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)


def sigma1(x):
    # ROTR 6(x) ⊕ ROTR 11(x) ⊕ ROTR 25(x)
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)


def gamma0(x):
    # ROTR 7(x) ⊕ ROTR 18(x) ⊕ SHR 3(x)
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ shift_right(x, 3)


def gamma1(x):
    # ROTR 17(x) ⊕ ROTR 19(x) ⊕ SHR 10(x)
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ shift_right(x, 10)


def mutate(data, digest):
    digest_copy = digest[:]

    # В хеш-вычислениях SHA-256 используются функции и константы, ранее
    # определенные в гл. 4.1.2 и гл. 4.2.2 соответственно
    # добавление (+) выполняется по модулю 232

    w = []
    for i in range(0, 16):
        w.append(sum([
            data[4 * i + 0] << 24,
            data[4 * i + 1] << 16,
            data[4 * i + 2] << 8,
            data[4 * i + 3] << 0,
        ]))

    for i in range(16, 64):
        sum_ = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]
        w.append(sum_ & 0xffffffff)

    for idx in xrange(0, -64, -1):
        i = abs(idx % 8)

        # Инициализируем восемь рабочих переменных a, b, c, d, e, f, g и h с помощью (i-1) -го хэш-значения.
        # W - подготовленное расписание сообщений
        positions = [(i + x) % 8 for x in xrange(8)]
        d_position = positions[3]
        h_position = positions[-1]
        a, b, c, d, e, f, g, h = [digest_copy[pos] for pos in positions]

        t1 = h + sigma1(e) + choose(e, f, g) + K256[abs(idx)] + w[abs(idx)]
        t2 = sigma0(a) + majority(a, b, c)
        digest_copy[d_position] = (d + t1) & 0xffffffff
        digest_copy[h_position] = (t1 + t2) & 0xffffffff

    return [(x + digest_copy[idx]) & 0xffffffff for idx, x in enumerate(digest)]


def get_buffer(s):
    if isinstance(s, str):
        return s
    if isinstance(s, unicode):
        try:
            return str(s)
        except UnicodeEncodeError:
            pass
    return buffer(s)


def zeros(count):
    return [0] * count


class SHA256(object):
    def __init__(self, string=None):
        self._sha = {
            'digest': INITIAL_HASH,
            'count_lo': 0,
            'count_hi': 0,
            'data': zeros(BLOCK_SIZE),
        }
        if not string:
            return
        buff = get_buffer(string)
        count = len(buff)
        count_lo = (self._sha['count_lo'] + (count << 3)) & 0xffffffff
        if count_lo < self._sha['count_lo']:
            self._sha['count_hi'] += 1
        self._sha['count_lo'] = count_lo
        self._sha['count_hi'] += (count >> 29)

        buffer_idx = 0
        while count >= BLOCK_SIZE:
            self._sha['data'] = [ord(c) for c in buff[buffer_idx:buffer_idx + BLOCK_SIZE]]
            count -= BLOCK_SIZE
            buffer_idx += BLOCK_SIZE
            self._sha['digest'] = mutate(self._sha['data'], self._sha['digest'])

        self._sha['data'][:count] = [ord(c) for c in buff[buffer_idx:buffer_idx + count]]

    def hexdigest(self):
        """
        Шестнадцатеричная цифра - это элемент множества {0, 1,…, 9, a,…, f}
        шестнадцатеричная цифра является представлением 4-битной строки
        например, шестнадцатеричная цифра «7» представляет 4-битную строку «0111»,
        а шестнадцатеричная цифра «a» представляет 4-битную строку «1010»
        """
        hash = self._sha.copy()
        count = (hash['count_lo'] >> 3) & 0x3f
        hash['data'][count] = 0x80
        count += 1
        if count > BLOCK_SIZE - 8:
            # fill with zero bytes after the count
            hash['data'] = hash['data'][:count] + zeros(BLOCK_SIZE - count)
            hash['digest'] = mutate(hash['data'], hash['digest'])
            # fill with zero bytes
            hash['data'] = [0] * BLOCK_SIZE
        else:
            hash['data'] = hash['data'][:count] + zeros(BLOCK_SIZE - count)

        for idx, shift in zip(range(56, 64), range(24, -1, -8) * 2):
            hash['data'][idx] = (hash['count_hi' if idx < 60 else 'count_lo'] >> shift) & 0xff

        hash['digest'] = mutate(hash['data'], hash['digest'])

        digest = []
        for i in hash['digest']:
            for shift in xrange(24, -1, -8):
                digest.append((i >> shift) & 0xff)
        return ''.join(['%.2x' % i for i in digest[:DIGEST_SIZE]])


def test():
    string = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
    assert 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == SHA256().hexdigest()
    assert 'a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433' == SHA256(string).hexdigest()
    assert 'db7b94909697ac91e9f167159b99a1d2612b5cf4b3086a72cb6ac0206c4bd47c' == SHA256(string * 7).hexdigest()
    assert '1aa4458852eefd69560827a035db9df11491abdae3483a71d1707f05e085e682' == SHA256('hello⊕').hexdigest()
    long_text = string * 999
    assert '5e4e5fcc4c89b7b1b6567d81187e83c99cd7c04ca77a093ed74e35a08046d519' == SHA256(long_text).hexdigest()
    assert 'c7ae9b6438e9dfccfd486fabed3c08d6f63ae559ef09b2fe084a38dbc46fae7c' == SHA256(u'\uE52D').hexdigest()
    print 'ok'


if __name__ == "__main__":
    test()
