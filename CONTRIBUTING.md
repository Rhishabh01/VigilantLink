# Contributing to VigilantLink

First off, thank you for considering contributing to VigilantLink! It's people like you that make VigilantLink a great tool for everyone.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

*   **Check the [Issue Tracker](https://github.com/VigilantLink/VigilantLink/issues)** to see if the bug has already been reported.
*   **Use the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md)** to provide detailed information about the issue.
*   Include steps to reproduce, expected behavior, and screenshots if applicable.

### Suggesting Enhancements

*   **Open a [Feature Request](https://github.com/VigilantLink/VigilantLink/issues/new)** and describe the feature you'd like to see.
*   Explain why this feature would be useful to most VigilantLink users.

### Pull Requests

1.  **Fork the repository** and create your branch from `main`.
2.  **Install dependencies** (see [Local Setup](#local-setup)).
3.  **Ensure your code follows our [Coding Guidelines](#coding-guidelines)**.
4.  **Add tests** for any new functionality.
5.  **Submit a Pull Request** with a clear description of the changes.

## Local Setup

### Backend (Python/FastAPI)

1.  Navigate to the `backend/` directory.
2.  Create a virtual environment: `python -m venv venv`
3.  Activate it: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows).
4.  Install dependencies: `pip install -r requirements.txt`
5.  Install Playwright browser: `playwright install chromium`
6.  Set up environment variables in a `.env` file (see `.env.example`).
7.  Run the server: `uvicorn app.main:app --host localhost --port 8000 --reload`

### Extension (Chrome MV3)

1.  Open Chrome and navigate to `chrome://extensions/`.
2.  Enable **Developer Mode**.
3.  Click **Load unpacked** and select the `extension/` directory.

## Development Workflow

*   **Branching**: Use descriptive branch names (e.g., `fix/typosquatting-logic`, `feat/firefox-support`).
*   **Commits**: Use clear, concise commit messages.
*   **Versioning**: We follow [Semantic Versioning](https://semver.org/).

## Coding Guidelines

*   **Python**: Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/). Use type hints where possible.
*   **JavaScript**: Follow standard ES6+ practices.
*   **Documentation**: Update `docs/` and `README.md` if your changes affect usage or architecture.

## Testing Expectations

*   Ensure that any logic changes in `scanner.py` or `orchestrator.py` are verified against real-world URLs.
*   Test both Phase 1 (heuristic) and Phase 2 (deep scan) flows.
*   Verify that the extension UI handles loading and error states gracefully.

## Question?

Feel free to open a discussion or contact the maintainers if you're unsure about anything!
