from requests import get


class UrlConnector:

    def __init__(self, url=""):
        self.url = url

    def get_hits_of_password(self, sha_to_find):
        response = get(self.url)
        counter = 0
        if self.url == "":
            return counter
        for line in response.text.splitlines():
            if line.split(':')[0].lower() == sha_to_find:
                return line.split(':')[1]
        return counter

    def set_url(self, new_url):
        self.url = new_url

# def get_number_of_leaks(self, five_first_signs_of_password_in_sha1):
