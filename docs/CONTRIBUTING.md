# Contributing to SecureVault

Thank you for your interest in contributing to SecureVault! We welcome contributions from the community to help improve this project.

## How to Contribute

1. **Fork** the repository and create your feature branch (`git checkout -b feature/AmazingFeature`)
2. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
3. **Push** to the branch (`git push origin feature/AmazingFeature`)
4. Open a **Pull Request**

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure_vault.git
   cd secure_vault
   ```

2. Set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the pinned development environment (including test and GUI
   dependencies):
   ```bash
   pip install -r requirements-dev.txt
   ```

4. Run the same repository-level validation used by CI:
   ```bash
   make validate
   ```

   This compiles every Python file, runs the complete suite and the focused Qt
   suite with `QT_QPA_PLATFORM=offscreen`, then runs flake8 and mypy. The mypy
   scope is temporarily limited to `auth_secrets.py`, which is the first clean
   production module; the repository maintainers own expanding that scope, and
   the limitation must be removed once the remaining production modules pass
   mypy. Flake8 currently enforces syntax and fatal pyflakes checks (`E9`,
   `F63`, and `F7`) across the repository. The maintainers also own that
   temporary rule exclusion, which must be removed in favor of an unfiltered
   `flake8 .` run once the existing style and undefined-name backlog is fixed.

   Dependency auditing runs separately in GitHub Actions against every
   supported requirements group: core, GUI, test, development, and optional
   platform integrations. There are currently no vulnerability exclusions; any
   future `pip-audit` ignore must name an owner and a concrete removal condition
   next to the ignore.

## Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints for better code clarity
- Write docstrings for all public functions and classes
- Keep lines under 88 characters (Black formatter default)

## Testing

- Write tests for new features and bug fixes
- Ensure all tests pass before submitting a pull request
- Add integration tests for critical security features

## Security

- Report security vulnerabilities privately to the maintainers
- Never commit sensitive data or credentials
- Follow secure coding practices

## Pull Request Process

1. Ensure your code passes all tests
2. Update documentation as needed
3. Add your name to CONTRIBUTORS.md (if it exists)
4. Request reviews from maintainers

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you are expected to uphold this code.
