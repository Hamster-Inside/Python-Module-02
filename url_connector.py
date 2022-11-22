"""Class for connecting with site and getting data"""
from requests import get


class UrlConnector:
    """Class handling the connection"""
    def __init__(self, url=""):
        """Sets initial url if needed"""
        self.url = url

    def get_hits_of_password(self, sha_to_find: str) -> int:
        """Checks site for password by sha1, and return number of how many times password leaked"""
        response = get(self.url, timeout=10)
        counter = 0
        if self.url == "":
            return counter
        for line in response.text.splitlines():
            if line.split(':')[0].lower() == sha_to_find.lower():
                return int(line.split(':')[1])
        return counter

    def set_url(self, new_url: str) -> None:
        """Sets new url"""
        self.url = new_url

    def get_url(self) -> str:
        """Return current url"""
        return self.url
# def get_number_of_leaks(self, five_first_signs_of_password_in_sha1):
