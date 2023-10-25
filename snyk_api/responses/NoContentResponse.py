from base_response import BaseResponse

class NoContentResponse(BaseResponse):
    def __init__(self) -> None:
        super().__init__(204)
