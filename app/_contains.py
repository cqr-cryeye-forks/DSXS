import re


def _contains(content, chars):
    content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content

    return all(char in content for char in chars)
