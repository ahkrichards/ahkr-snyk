from base_response import BaseResponse

class ConflictResponse(BaseResponse):
    def __init__(self) -> None:
        super().__init__(409)
