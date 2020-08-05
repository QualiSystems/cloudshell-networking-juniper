from cloudshell.shell.flows.utils.networking_utils import UrlParser


def get_url_without_password(url):
    url_dict = UrlParser.parse_url(url)
    url_dict[UrlParser.PASSWORD] = ""
    url_dict[UrlParser.NETLOC] = ""
    return UrlParser.build_url(url_dict)


def get_url_scheme(url):
    return UrlParser.parse_url(url)[UrlParser.SCHEME]


def get_url_password(url):
    return UrlParser.parse_url(url)[UrlParser.PASSWORD]
