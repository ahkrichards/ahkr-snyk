class BaseResponse:
    def __init__(self, http_status_code: int) -> None:
        self.http_status_code = http_status_code
