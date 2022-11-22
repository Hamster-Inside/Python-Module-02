""" Small Script to show if password has leaked """
import typing
import logging
import password_validator
import url_connector

logging.basicConfig(filename=r'Logs\module_02_logs.log', encoding='utf-8', level=logging.INFO)

# Password:
# check if password is not on site 'have i been pwnd'
# write passwords in passwords.txt
# write safe passwords to safe.txt
# use logger to save in file

validator = password_validator.PasswordValidator()

PASSWORDS_FILE_NAME = "passwords.txt"
SAFE_PASSWORDS_FILE_NAME = "safe_passwords.txt"
UNSAFE_PASSWORDS_FILE_NAME = "unsafe_passwords.txt"


def create_safe_and_unsafe_files(files_dir: str,
                                 passwords_file_name: str,
                                 safe_passwords_file: str,
                                 unsafe_passwords_file: str) -> None:
    """Writes passwords which are safe and unsafe to corresponding file"""

    with open(files_dir + passwords_file_name, encoding="UTF-8") as input_file, open(
              files_dir + safe_passwords_file, mode='w', encoding="UTF-8") as safe_output, open(
              files_dir + unsafe_passwords_file, mode='w', encoding="UTF-8") as unsafe_output:
        for line in input_file:
            if validator.check_if_password_is_strong_enough(line):
                safe_output.write(line)
            else:
                unsafe_output.write(line)


connection = url_connector.UrlConnector()

DIRECTORY_OF_FILES = "Secrets/"


# print(connection.get_data())

def get_list_of_passwords_from_file(passwords_file_name: str) -> typing.List:
    """Returns list of passwords from txt file"""
    pass_list = []
    with open(DIRECTORY_OF_FILES + passwords_file_name, encoding="UTF-8", mode='r') as input_file:
        for line in input_file:
            pass_list.append(line.strip())
    return pass_list


create_safe_and_unsafe_files(DIRECTORY_OF_FILES,
                             PASSWORDS_FILE_NAME,
                             SAFE_PASSWORDS_FILE_NAME,
                             UNSAFE_PASSWORDS_FILE_NAME)

passwords_list = get_list_of_passwords_from_file(PASSWORDS_FILE_NAME)
for current_password in passwords_list:
    HITS_OF_PASS = 0
    CURRENT_SHA1 = validator.change_to_sha1(current_password)
    ADD_TO_URL = CURRENT_SHA1[0:5]
    REST_OF_THE_SHA1 = CURRENT_SHA1[5:]
    connection.set_url('https://api.pwnedpasswords.com/range/' + ADD_TO_URL)
    number_of_leaks = connection.get_hits_of_password(REST_OF_THE_SHA1)
    print(f'{current_password} --> {number_of_leaks}')

logging.warning('cat')
