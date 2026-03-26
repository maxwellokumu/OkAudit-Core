# Contributing to IT Audit Team Skills

Thank you for your interest in contributing to the IT Audit Team Skills repository! This project aims to provide a comprehensive set of Claude AI skills for IT auditors.

## How to Contribute

### 1. Development Setup
```bash
git clone https://github.com/your-org/it-audit-team-skills.git
cd it-audit-team-skills
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Adding New Skills
- Follow the established folder structure: `role/skill-name/`
- Include `skill.yaml`, `main.py`, `README.md`, and `sample_input/` for data-driven skills
- Ensure full type hints, Google-style docstrings, and argparse CLI
- Add realistic sample data in `sample_input/`
- Update the main `README.md` with the new skill

### 3. Code Standards
- Python 3.8+ with full type hints
- Google-style docstrings for all functions and classes
- `argparse` for CLI interfaces
- Graceful error handling with meaningful error messages
- `if __name__ == "__main__":` guards

### 4. Testing
- Add unit tests in `tests/test_[role].py`
- Run tests with `pytest tests/ -v`
- Ensure all tests pass before submitting PR

### 5. Pull Request Process
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Run tests: `pytest tests/`
5. Commit with conventional format: `feat: add new skill for XYZ`
6. Push to your fork
7. Create a Pull Request with a clear description

### 6. Commit Message Format
Use conventional commits:
- `feat: add new skill` for new features
- `fix: correct issue in XYZ` for bug fixes
- `docs: update README` for documentation
- `test: add tests for ABC` for test additions

### 7. Reporting Issues
- Use GitHub Issues for bug reports and feature requests
- Include steps to reproduce, expected vs actual behavior
- Tag with appropriate labels

## License
By contributing, you agree that your contributions will be licensed under the MIT License.