import pathlib

ROOT_PATH = pathlib.Path(__file__).parent.parent.absolute()
APP_PATH = ROOT_PATH / "app"
AGENTS_PATH = APP_PATH.joinpath("agents.txt")
