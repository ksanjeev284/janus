# Contributing to Janus Security

Thank you for your interest in contributing to Janus! We welcome contributions from the community to help make API security accessible to everyone.

## Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/your-username/janus.git
    cd janus
    ```
3.  **Install dependencies**:
    ```bash
    pip install -e .
    ```

## Development Workflow

1.  Create a new branch for your feature or bugfix:
    ```bash
    git checkout -b feature/amazing-feature
    ```
2.  Make your changes.
3.  Run tests to ensure everything is working:
    ```bash
    # Run CLI tests
    janus --help
    ```
4.  Commit your changes:
    ```bash
    git commit -m "Add amazing feature"
    ```
5.  Push to your fork:
    ```bash
    git push origin feature/amazing-feature
    ```
6.  Open a **Pull Request** on the main repository.

## Coding Standards

-   Follow PEP 8 style guidelines.
-   Use type hints for function arguments and return values.
-   Add comments for complex logic.
-   Update documentation if you change CLI commands or API features.

## Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub. Include:
-   Steps to reproduce.
-   Expected vs. actual behavior.
-   Environment details (OS, Python version).

## Release Process

Janus uses automated workflows for releases. To publish a new version to PyPI:

1.  **Bump Version**: Update `version` in `pyproject.toml` (e.g., `0.2.0`).
2.  **Commit**: Commit the version change.
3.  **GitHub Release**:
    -   Go to the repository on GitHub.
    -   Click "Releases" -> "Draft a new release".
    -   Tag version: `v0.2.0`.
    -   Title: `v0.2.0 - Feature Name`.
    -   Click "Publish release".
4.  **Automation**: The GitHub Action will automatically build and upload to PyPI (requires `PYPI_API_TOKEN` secret).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
