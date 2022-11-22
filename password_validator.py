"""Module for checking password"""
import re
from hashlib import sha1


class PasswordValidator:
    """Class for validating the password and working with sha1 encoding"""

    def check_if_password_is_strong_enough(self, password: str) -> bool:
        """Function for checking if password is strong enough"""
        eight_sign_check = len(password) >= 8
        one_number_check = bool(re.search(r'\d', password))
        one_special_sign_check = bool(re.compile(r'[@_!#$%^&*()<>?/\|}{~:]').search(password))
        lowercase_and_uppercase_check = bool(re.search('[A-Z]', password))

        return all([eight_sign_check,
                    one_number_check,
                    one_special_sign_check,
                    lowercase_and_uppercase_check])

    def change_to_sha1(self, password: str) -> str:
        """Function for changing standard password as string to sha1"""
        return (sha1(password.encode('UTF-8'))).hexdigest()
