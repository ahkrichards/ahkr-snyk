from base_response import BaseResponse

class InternalServerErrorResponse(BaseResponse):
    def __init__(self) -> None:
        super().__init__(500)
