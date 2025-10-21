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

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run tests:
   ```bash
   python -m pytest
   ```

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
