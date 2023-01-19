from django.test import SimpleTestCase
import re
import random
import string


class FormTests(SimpleTestCase):

    def test_email_regex(self):
        TLD_SUCC = ['@gmail.com', '@yandex.ru']
        TLD_FAIL = [
            '@yahoo.com',
            '@email.com',
            '@rangom_TLD.random',
            '_yandex.ru',
            '@yandex..ru',
            '@yandx.ru',
            '@ggle.com',
            '@google.cm'
            ]

        letters = string.ascii_letters
        digits = string.digits
        pattern = re.compile(r'[a-zA-Z\d]{5,50}(@gmail.com|@yandex.ru)')

        # all_right
        for i in TLD_SUCC:
            success_str = 'asdAxsdda3123ad'
            success_str += i
            self.assertTrue(re.fullmatch(pattern, success_str))

        # wrong_length
        err = ['oajbieii8B4p6dzn1mKhBjqHyd2YNT4du3RZrDIv1C8rJ7sddas@gmail.com', 'asd@gmail.com']
        for i in err:
            self.assertFalse(re.fullmatch(pattern, i))
        
        # symbols
        err = ['oajbieii8B4p6dzn1mKhBjqHyd2Y T4du3@C8rJ7sddas@gmail.com', 'asd.asd@gmail.com']
        for i in err:
            self.assertFalse(re.fullmatch(pattern, i))
        
        # wrong TLD
        for i in TLD_FAIL:
            rand_length = random.randint(5, 50)
            result_str = ''.join(random.choice(letters + digits) for _ in range(rand_length))
            result_str += i
            self.assertFalse(re.fullmatch(pattern, result_str))