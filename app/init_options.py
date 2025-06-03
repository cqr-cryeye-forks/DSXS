import urllib

from app.constants import COOKIE, UA, NAME, REFERER


def init_options(proxy=None, cookie=None, random_agent=None, referer=None) -> dict:
    headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, random_agent or NAME), (REFERER, referer))))
    # headers = dict(filter(lambda _: _[1], ((cookie, COOKIE), (random_agent, UA or NAME), (referer, REFERER))))

    urllib.request.install_opener(
        urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy})) if proxy else None)

    return headers
