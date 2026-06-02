# config.py

## Purpose
One place that loads all settings from the `.env` file and makes them available
to every other module. No other file reads `.env` directly.

## Why it exists
Without this, every module would need to call `load_dotenv()` and read
`os.environ` on its own. If you ever change a variable name, you'd have to
update it in 10 places. With `config.py`, you change it once.

## Key concepts

### @dataclass
A Python shortcut for a class that just holds data.
Instead of writing `__init__` manually, you declare fields with their types and defaults:
```python
@dataclass
class Config:
    ssh_port: int = 2222
```

### load_dotenv()
Reads the `.env` file and pushes each line into `os.environ`:
```
.env line:  SSH_PORT=3333
result:     os.environ["SSH_PORT"] = "3333"
```

### os.environ.get("SSH_PORT", 2222)
Reads the value from the environment. The second argument is the default —
used when the variable is not set in `.env`.
Everything from `.env` is a string, so we wrap with `int()` for port numbers.

### pathlib.Path
Wraps directory strings so we can build paths cleanly later:
```python
config.data_dir / "honeypot.db"   # → data/honeypot.db
```

### mkdir(parents=True, exist_ok=True)
Creates the `data/` and `logs/` folders at startup if they don't exist yet.
`exist_ok=True` means no error if the folder is already there.

## How other modules use it
```python
from honeypot.core.config import load_config

config = load_config()
print(config.ssh_port)      # 2222
print(config.data_dir)      # data/
```

## Flow
```
.env file
    ↓
load_dotenv()  →  pushes into os.environ
    ↓
Config(ssh_port=int(os.environ.get(...)), ...)
    ↓
mkdir data/ and logs/
    ↓
returns Config object
```
