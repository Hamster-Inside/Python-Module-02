"""Module for checking password"""
from hashlib import sha1
from abc import ABC, abstractmethod
from requests import get


class ValidationError(Exception):
    """ Exception for validation error """


class Validator(ABC):
    """ Interface for validators """

    @abstractmethod
    def __init__(self, text: str):
        """ Force to implement __init__ method """

    @abstractmethod
    def is_valid(self) -> bool:
        """ Force to implement is_valid method """


class LengthValidator(Validator):
    """ Validator that checks if text has enough characters """

    def __init__(self, text: str, min_text_length=8):
        self.text = text
        self.min_text_length = min_text_length

    def is_valid(self) -> bool:
        """ Checks if text is valid

        Raises:
            ValidationError: text is not valid because it hasn't minimum required number of letters

        Returns:
            bool: text has minimum required number of letters

        """
        if len(self.text) >= self.min_text_length:
            return True
        raise ValidationError('Password is too short')


class OneNumberValidator(Validator):
    """ Validator that checks if text has at least one number """

    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        """ Checks if text is valid

        Raises:
            ValidationError: text is not valid because it is missing at least one number

        Returns:
            bool: text has at least one number

        """
        for num in range(0, 10):
            if str(num) in self.text:
                return True
        raise ValidationError('Password need at least one number')


class OneSpecialSignValidator(Validator):
    """ Validator that checks if text has at least one special sign """

    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        """ Checks if text is valid

               Raises:
                   ValidationError: text is not valid because
                   it is missing at least one special sign

               Returns:
                   bool: text has one special sign

               """
        if any(not character.isalnum() for character in self.text):
            return True
        raise ValidationError('Password need one special sign')


class LowercaseValidator(Validator):
    """ Validator that checks if text has at least one lowercase letter """

    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        """ Checks if text is valid

               Raises:
                   ValidationError: text is not valid because
                   it is missing at least one lowercase letter

               Returns:
                   bool: text has at least one lowercase letter

               """
        if any(character.islower() for character in self.text):
            return True
        raise ValidationError('Password need one lowercase letter')


class UppercaseValidator(Validator):
    """ Validator that checks if text has at least one uppercase letter """

    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        """ Checks if text is valid

        Raises:
            ValidationError: text is not valid because it is missing at least one uppercase letter

        Returns:
            bool: text has at least one uppercase letter

        """
        if any(character.isupper() for character in self.text):
            return True
        raise ValidationError('Password need one uppercase letter')


class HaveIBeenPwndValidator(Validator):
    """ Validator that checks if text appears in haveibeenpwnd list of leaked passwords """

    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        """ Checks if text is valid

        Raises:
          ValidationError: text is not valid because
          it is found on haveibeenpwnd site and is not safe to use

        Returns:
          bool: text has not leaked

        """
        encoded_password = (sha1(self.text.encode('UTF-8'))).hexdigest().upper()
        url = 'https://api.pwnedpasswords.com/range/'
        response = get(url + encoded_password[:5], timeout=10)
        for line in response.text.splitlines():
            if line.split(':')[0].upper() == encoded_password[5:]:
                raise ValidationError('Password leaked, need to change password')
        return True


class PasswordValidator(Validator):
    """ Validator to check if text is strong enough as a password"""

    def __init__(self, text: str, min_text_length=8):
        self.min_text_length = min_text_length
        self.text = text
        self.validators = [
            LengthValidator,
            OneNumberValidator,
            OneSpecialSignValidator,
            LowercaseValidator,
            UppercaseValidator,
            HaveIBeenPwndValidator
        ]

    def is_valid(self) -> bool:
        """ Checks if text is valid

        Returns:
          bool: returns True if passes all the validators requirements

        """
        validation_list = []
        for new_validator in self.validators:
            if new_validator == LengthValidator and self.min_text_length != 8:
                validator = new_validator(self.text, self.min_text_length)
            else:
                validator = new_validator(self.text)
            validation_list.append(validator.is_valid())
        return all(validation_list)
