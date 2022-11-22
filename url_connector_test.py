from url_connector import UrlConnector

url_connector = UrlConnector()


def test_get_hits_of_password(requests_mock):
    url = 'https://api.pwnedpasswords.com/range/a94a8'
    data = '007279035BE63272C81B84BD8B07D25D7E5:10\n010B55A0CE243B3AA85FC808ACBEB97FFA3:2'
    url_connector.set_url(url)
    requests_mock.get(url, text=data)
    assert url_connector.get_hits_of_password('007279035BE63272C81B84BD8B07D25D7E5') == 10
    assert url_connector.get_hits_of_password('010B55A0CE243B3AA85FC808ACBEB97FFA3') == 2
