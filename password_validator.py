"""Module for checking password"""
import re
from hashlib import sha1
from abc import ABC, abstractmethod
from requests import get


class ValidationError(Exception):
    pass


class Validator(ABC):
    @abstractmethod
    def __init__(self, text: str):
        pass

    @abstractmethod
    def is_valid(self) -> bool:
        pass


class LengthValidator(Validator):

    def __init__(self, text: str, min_text_length=8):
        self.text = text
        self.min_text_length = min_text_length

    def is_valid(self) -> bool:
        if len(self.text) >= self.min_text_length:
            return True
        else:
            raise ValidationError('Password is too short')


class OneNumberValidator(Validator):
    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        # return bool(re.search(r'\d', self.text))
        for num in range(0, 10):
            if str(num) in self.text:
                return True
        raise ValidationError('Password need at least one number')


class OneSpecialSignValidator(Validator):
    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        # return bool(re.compile(r'[@_!#$%^&*()<>?/\|}{~:]').search(self.text))
        if any([not character.isalnum() for character in self.text]):
            return True
        else:
            raise ValidationError('Password need one special sign')


class LowercaseValidator(Validator):
    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        # return bool(re.search('[A-Z]', self.text))
        if any([character.islower() for character in self.text]):
            return True
        else:
            raise ValidationError('Password need one lowercase letter')


class UppercaseValidator(Validator):

    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        if any([character.isupper() for character in self.text]):
            return True
        else:
            raise ValidationError('Password need one uppercase letter')


class HaveIBeenPwndValidator(Validator):

    def __init__(self, text: str):
        self.text = text

    def is_valid(self) -> bool:
        encoded_password = (sha1(self.text.encode('UTF-8'))).hexdigest().upper()
        url = 'https://api.pwnedpasswords.com/range/'
        response = get(url + encoded_password[:5], timeout=10)
        for line in response.text.splitlines():
            if line.split(':')[0].upper() == encoded_password[5:]:
                raise ValidationError('Password leaked, need to change password')
        return True


class PasswordValidator(Validator):
    """Class for validating the password"""

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
        validation_list = []
        for new_validator in self.validators:
            if new_validator == LengthValidator and self.min_text_length != 8:
                validator = new_validator(self.text, self.min_text_length)
            else:
                validator = new_validator(self.text)
            validation_list.append(validator.is_valid())
        return all(validation_list)

