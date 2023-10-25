from base_response import BaseResponse

class ForbiddenResponse(BaseResponse):
    def __init__(self) -> None:
        super().__init__(403)
