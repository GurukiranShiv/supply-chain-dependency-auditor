# Release Checklist

1. Update `auditor/version.py` and `pyproject.toml`.
2. Run tests:

   ```powershell
   python -m unittest discover -s tests -v
   ```

3. Build and validate package:

   ```powershell
   python -m pip install --upgrade build twine
   python -m build
   python -m twine check dist/*
   ```

4. Upload to TestPyPI first.
5. Create a GitHub release after validation.
6. Let the PyPI trusted-publishing workflow publish the release.
7. Confirm docs deploy successfully with MkDocs/GitHub Pages.
