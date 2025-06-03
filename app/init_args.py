import pathlib
import argparse


def init_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_argument("--data", help="POST data (e.g. \"query=test\")")
    parser.add_argument("--cookie", help="HTTP Cookie header value")
    parser.add_argument("--random-agent", help="Random HTTP User-Agent header", action="store_true", default=True)
    parser.add_argument("--referer", help="HTTP Referer header value")
    parser.add_argument("--proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    parser.add_argument('-o', '--output-file', default='results.json', type=pathlib.Path, help='Output file for JSON results')

    return parser.parse_args()