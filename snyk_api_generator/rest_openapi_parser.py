import json


class RestOpenApiParser:
    def __init__(self, file: str):
        self._load_from_file(file)

    def _load_from_file(self, file: str) -> None:
        with open(file, "r") as _file:
            self.data: dict = json.load(_file)

    def get_component_headers(self) -> list[dict]:
        # TODO: Handle KeyErrors
        return self.data["components"]["headers"]
    
    def get_component_parameters(self) -> list[dict]:
        # TODO: Handle KeyErrors
        return self.data["components"]["parameters"]
    
    def get_component_responses(self) -> list[dict]:
        # TODO: Handle KeyErrors
        return self.data["components"]["responses"]

    def get_snyk_api_version(self) -> str:
        snyk_api_version: str = None

        if "x-snyk-api-version" not in self.data.keys():
            raise Exception("TODO: Make more helpful than just standard KeyError")

        snyk_api_version = self.data["x-snyk-api-version"]

        return snyk_api_version

    def get_base_url(self) -> str:
        base_url: str = None

        if "servers" not in self.data.keys():
            raise Exception("TODO: Make more helpful than just standard KeyError")

        for item in self.data["servers"]:
            if "description" in item.keys() and item["description"] == "Snyk REST API":
                base_url = item["url"]
                break

        if base_url is None:
            raise Exception(
                "Something has gone terribly unexpected! TODO: Be more helpful"
            )

        return base_url
