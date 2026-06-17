# Release to PyPI

V9 includes PyPI-ready packaging metadata and release workflows.

## Local build

```powershell
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

## TestPyPI upload

```powershell
python -m twine upload --repository testpypi dist/*
```

## PyPI upload

```powershell
python -m twine upload dist/*
```

## GitHub trusted publishing

The included `publish-pypi.yml` workflow is designed for PyPI Trusted Publishing. Configure the PyPI project to trust the GitHub repository and workflow environment before running the release.
