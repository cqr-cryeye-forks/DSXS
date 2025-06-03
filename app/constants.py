NAME, VERSION, AUTHOR, LICENSE = "Damn Small XSS Scanner (DSXS) < 100 LoC (Lines of Code)", "0.3c", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"  # optional HTTP header names

SMALLER_CHAR_POOL = ('<', '>')  # characters used for XSS tampering of parameter values (smaller set - for avoiding possible SQLi errors)
LARGER_CHAR_POOL = ('\'', '"', '>', '<', ';')  # characters used for XSS tampering of parameter values (larger set)
GET, POST = "GET", "POST"  # enumerator-like values used for marking current phase
PREFIX_SUFFIX_LENGTH = 5  # length of random prefix/suffix used in XSS tampering
DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"  # filtering regex used before DOM XSS search

REGULAR_PATTERNS = (
    # each (regular pattern) item consists of (r"context regex", (prerequisite unfiltered characters), "info text", r"content removal regex")
    (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'),
     "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'),
     "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering",
     r"\\'|{[^\n]+}"),
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'),
     "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering",
     r'\\"|{[^\n]+}'),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',),
     "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering",
     r"&(#\d+|[a-z]+);|'[^'\s]+'|\"[^\"\s]+\"|{[^\n]+}"),
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*=\s*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',),
     "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r'<[^>]*=\s*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',),
     "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->|=\s*'[^']*'|=\s*\"[^\"]*\""),
)

DOM_PATTERNS = (  # each (dom pattern) item consists of r"recognition regex"
    r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>",
    r"(?s)<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location).*?</script>",
)

TIMEOUT = 30  # connection timeout in seconds
