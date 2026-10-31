class ScopeViolationError(Exception):
    pass

class RedirectLimitExceeded(Exception):
    pass

class NonComparableResponseError(Exception):
    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__(f"Non-comparable response: {status_code}")
