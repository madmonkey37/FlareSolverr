import random
import string
from typing import Any, Dict
from selenium.webdriver.chrome.webdriver import WebDriver


SESSIONS: Dict[str, "SessionItem"] = {}


def get_random_session_id() -> str:
    ran = ''.join(random.choices(string.ascii_letters + string.digits, k = 12))    
    return ran


class SessionItem:
    session_id: str
    driver: WebDriver

    def __init__(self, *, session_id: str, driver: WebDriver) -> None:
        self.session_id = session_id
        self.driver = driver

