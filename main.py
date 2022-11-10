import password_validator, url_connector
import logging
logging.basicConfig(filename='Logs\module_02_logs.log', encoding='utf-8', level=logging.INFO)

# Password:
# check if password is not on site 'have i been pwnd'
# write passwords in passwords.txt
# write safe passwords to safe.txt
# use logger to save in file

validator = password_validator.PasswordValidator()

passwords_file_name = "passwords.txt"
safe_passwords_file_name = "safe_passwords.txt"
unsafe_passwords_file_name = "unsafe_passwords.txt"


def create_safe_and_unsafe_files(passwords_file_name, safe_passwords_file_name, unsafe_passwords_file_name):
    directory_of_files = "Secrets/"
    list_of_passworods = []
    with open(directory_of_files + passwords_file_name) as input_file, open(
            directory_of_files + safe_passwords_file_name, mode='w') as safe_output_file, open(
        directory_of_files + unsafe_passwords_file_name, mode='w') as unsafe_output_file:
        for line in input_file:
            if validator.check_if_password_is_strong_enough(line):
                safe_output_file.write(line)
            else:
                unsafe_output_file.write(line)


connection = url_connector.UrlConnector()

directory_of_files = "Secrets/"


# print(connection.get_data())

def get_list_of_passwords_from_file(passwords_file_name):
    list = []
    with open(directory_of_files + passwords_file_name, mode='r') as input_file:
        for line in input_file:
            list.append(line.strip())
    return list


create_safe_and_unsafe_files(passwords_file_name, safe_passwords_file_name, unsafe_passwords_file_name)

passwords_list = get_list_of_passwords_from_file(passwords_file_name)
for current_password in passwords_list:
    hits_of_pass = 0
    current_sha1 = validator.change_to_sha1(current_password)
    add_to_url = current_sha1[0:5]
    rest_of_the_sha1 = current_sha1[5:]
    connection.set_url('https://api.pwnedpasswords.com/range/' + add_to_url)
    number_of_leaks = connection.get_hits_of_password(rest_of_the_sha1)
    print(f'{current_password} --> {number_of_leaks}')

logging.warning('cat')