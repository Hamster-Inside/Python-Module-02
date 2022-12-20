import typing


class FilesManager:

    def __init__(self, directory="Secrets/"):
        self.DIRECTORY_OF_FILES = directory
        self.PASSWORDS_FILE_NAME = "passwords.txt"
        self.SAFE_PASSWORDS_FILE_NAME = "safe_passwords.txt"
        self.UNSAFE_PASSWORDS_FILE_NAME = "unsafe_passwords.txt"
        self.create_safe_and_unsafe_files()
        self.passwords_list = []

    def create_safe_and_unsafe_files(self) -> None:
        with open(
                self.DIRECTORY_OF_FILES + self.PASSWORDS_FILE_NAME, encoding="UTF-8") as input_file, open(
            self.DIRECTORY_OF_FILES + self.SAFE_PASSWORDS_FILE_NAME, mode='w', encoding="UTF-8") as safe_output, open(
            self.DIRECTORY_OF_FILES + self.UNSAFE_PASSWORDS_FILE_NAME, mode='w', encoding="UTF-8") as unsafe_output:
            pass

    def get_list_of_passwords(self) -> typing.List:
        """Returns list of passwords from txt file"""
        return self.passwords_list


file = FilesManager()
