"""expiry - track expiring secrets, certificates and anything else."""

from importlib.metadata import PackageNotFoundError, version

try:  # set at build time from the git tag (see pyproject.toml, [tool.setuptools_scm])
    __version__ = version("expiry")
except PackageNotFoundError:  # running from a source checkout without installing
    __version__ = "0.0.0+unknown"
