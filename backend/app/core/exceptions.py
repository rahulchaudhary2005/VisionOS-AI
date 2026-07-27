class VisionOSException(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class DatabaseException(VisionOSException):
    pass


class AIEngineException(VisionOSException):
    pass


class CameraException(VisionOSException):
    pass


class AuthenticationException(VisionOSException):
    pass