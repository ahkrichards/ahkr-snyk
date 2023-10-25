from base_response import BaseResponse

class NotFoundResponse(BaseResponse):
    def __init__(self) -> None:
        super().__init__(404)
