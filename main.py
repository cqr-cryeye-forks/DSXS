import json
import pathlib
import random

from app.constants import VERSION, NAME, AUTHOR
from app.init_args import init_args
from app.init_options import init_options
from app.paths import AGENTS_PATH
from app.scan_page import scan_page


if __name__ == "__main__":
    print(f"{NAME} #v{VERSION}\n by: {AUTHOR}\n")

    args = init_args()
    url: str = args.url
    output_file: pathlib.Path = args.output_file
    random_agent: bool = args.random_agent

    data: str | None = args.data if args.data else None
    cookie: str | None = args.cookie if args.cookie else None
    referer: str | None = args.referer if args.referer else None
    proxy: str | None = args.proxy if args.proxy else None

    if random_agent:
        with open(AGENTS_PATH, "r") as f:
            user_agents = f.read().splitlines()
        random_agent = random.choice(user_agents)
        print(f"Chosen user-agent {random_agent}")

    headers: dict = init_options(
        proxy=proxy,
        cookie=cookie,
        random_agent=random_agent,
        referer=referer,
    )

    result: dict = scan_page(
        url=url if url.startswith("http") else f"http://{url}",
        data=data,
        headers=headers,
    )

    json_data = json.dumps(result)
    output_file.write_text(json_data)
    print(f"Final results save to {output_file.absolute().as_uri()}")
