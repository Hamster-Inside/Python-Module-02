""" Small Script to show if password has leaked """
import typing
import logging
import password_validator

logging.basicConfig(filename=r'Logs\module_02_logs.log', encoding='utf-8', level=logging.INFO)

# Password:
# check if password is not on site 'have i been pwnd'
# write passwords in passwords.txt
# write safe passwords to safe.txt
# use logger to save in file

validator = password_validator.PasswordValidator



for current_password in passwords_list:
    HITS_OF_PASS = 0
    CURRENT_SHA1 = validator.change_to_sha1(current_password)
    ADD_TO_URL = CURRENT_SHA1[0:5]
    REST_OF_THE_SHA1 = CURRENT_SHA1[5:]
    print(f'{current_password} --> {number_of_leaks}')
    logging.warning(f'Password {current_password} leaked {number_of_leaks} times')


