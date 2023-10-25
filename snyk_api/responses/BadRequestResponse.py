from base_response import BaseResponse

class BadRequestResponse(BaseResponse):
    def __init__(self) -> None:
        super().__init__(400)
