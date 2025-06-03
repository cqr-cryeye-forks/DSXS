import random
import re
import string
import urllib
import urllib.parse
import urllib.request

from app._contains import _contains
from app._retrieve_content import _retrieve_content
from app.constants import DOM_FILTER_REGEX, DOM_PATTERNS, PREFIX_SUFFIX_LENGTH, GET, POST, LARGER_CHAR_POOL, \
    SMALLER_CHAR_POOL, REGULAR_PATTERNS


def scan_page(url, headers: dict, data=None) -> dict:
    result: dict = {
        "possible_xss_vulnerable": False,
        "severity_level": "info",
        "xss": [],
    }

    url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>",
                                                                           data) if data else data
    original = re.sub(DOM_FILTER_REGEX, "", _retrieve_content(url=url, data=data, headers=headers))
    dom = next(filter(None, (re.search(_, original) for _ in DOM_PATTERNS)), None)
    if dom:
        print("Page itself appears to be XSS vulnerable (DOM)")
        result['possible_xss_vulnerable'] = True
        result["severity_level"] = "low"
        print(f"{dom.group(0)}")
        result["possible_xss"] = dom.group(0).replace("<script>", "").replace("</script>", "").strip()

    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):
                found, usable = False, True
                print(f"* scanning {phase} parameter '{match.group('parameter')}'")

                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in
                                  range(2))
                for pool in (LARGER_CHAR_POOL, SMALLER_CHAR_POOL):
                    if not found:
                        injection = (
                            f"{'`' if pool == LARGER_CHAR_POOL else ''}{prefix}"
                            f"{''.join(random.sample(pool, len(pool)))}{suffix}"
                        )
                        tampered = current.replace(
                            match.group(0),
                            f"{match.group(0)}{urllib.parse.quote(injection)}"
                        )

                        content = (
                            _retrieve_content(url=tampered, data=data, headers=headers)
                            if phase is GET else
                            _retrieve_content(url=url, data=tampered, headers=headers)
                        )
                        prefix_with_optional_char = f"{'`' if pool == LARGER_CHAR_POOL else ''}{prefix}"
                        content = content.replace(prefix_with_optional_char, prefix)

                        for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                            filtered = re.sub(content_removal_regex or "", "", content)
                            for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), filtered, re.I):
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)
                                if context and not found and sample.group(1).strip():
                                    if _contains(sample.group(1), condition):
                                        is_filtered = all(char in sample.group(1) for char in LARGER_CHAR_POOL)
                                        filtering_status = "no" if is_filtered else "some"
                                        print(
                                            f" (i) {phase} parameter '{match.group('parameter')}' appears to be "
                                            f"XSS vulnerable ({info % {'filtering': filtering_status} })"
                                        )
                                        result["xss"].append({
                                            "parameter": match.group("parameter"),
                                            "method": phase,
                                            "payload": injection,
                                            "filtering": filtering_status,
                                            "context": context.group(0) if context else None,
                                            "sample": sample.group(1)
                                        })

                                        found = True
                                        result["severity_level"] = "medium"

                                    break

    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")

    return result
