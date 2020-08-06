class BaseJuniperError(Exception):
    """Base Juniper Error."""


class NotSupportedJunOSError(BaseJuniperError):
    """Not supported by JunOS."""
