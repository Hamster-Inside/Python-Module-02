import re
from hashlib import sha1

class PasswordValidator:

    def check_if_password_is_strong_enough(self, password: str) -> bool:
        eight_sign_check = True if len(password) >= 8 else False
        one_number_check = bool(re.search(r'\d', password))
        one_special_sign_check = bool(re.compile('[@_!#$%^&*()<>?/\|}{~:]').search(password))
        lowercase_and_uppercase_check = bool(re.search('[A-Z]', password))

        return all([eight_sign_check, one_number_check, one_special_sign_check, lowercase_and_uppercase_check])

    def change_to_sha1(self, password):
        return (sha1(password.encode('UTF-8'))).hexdigest()
