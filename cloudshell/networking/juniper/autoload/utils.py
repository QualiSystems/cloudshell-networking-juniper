def strip_max_len(string: str, max_len: int) -> str:
    if len(string) > max_len:
        string = string[: max_len - 4] + " ..."
    return string


def strip_max_cs_len(string: str) -> str:
    return strip_max_len(string, 255)
