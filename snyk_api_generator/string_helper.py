from re import sub

class str(str):
    def camel_case(s: str) -> str:
        return sub(r"(_|-)+", " ", s).title().replace(" ", "")
