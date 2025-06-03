import urllib

from app.constants import TIMEOUT


def _retrieve_content(url, headers: dict, data=None):
    try:
        req = urllib.request.Request(
            "".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in range(len(url))),
            data.encode("utf8", "ignore") if data else None, headers)
        retval = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        retval = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
    return (retval.decode("utf8", "ignore") if hasattr(retval, "decode") else "") or ""
