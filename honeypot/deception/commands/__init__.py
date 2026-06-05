from .filesystem import handle_filesystem
from .core      import handle_core
from .system    import handle_system
from .network   import handle_network
from .package   import handle_package
from .service   import handle_service

COMMAND_HANDLERS = [
    handle_filesystem,
    handle_core,
    handle_system,
    handle_network,
    handle_package,
    handle_service,
]
