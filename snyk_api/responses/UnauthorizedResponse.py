from base_response import BaseResponse

class UnauthorizedResponse(BaseResponse):
    def __init__(self) -> None:
        super().__init__(401)
