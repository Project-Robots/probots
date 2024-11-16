.PHONY: clean build test docs upload

# Install dependencies for development
dev:
	pip install -r dev-requirements.txt

# Install dependencies for production
prod:
	pip install -r requirements.txt

# Format code with black
black:
	black .

# Sort imports with isort
isort:
	isort .

# Run flake8 linter
flake8:
	flake8 .

# Build documentation with sphinx
docs:
	sphinx-build -b html docs/ docs/_build

# Build the python package
build:
	python setup.py sdist bdist_wheel

# Run tests with pytest
test:
	pytest

# Run tests with pytest and coverage
coverage:
	coverage run -m pytest
	coverage report
	coverage html

# Run security checks with bandit
bandit:
	bandit -r . --exclude tests

# Run security checks with safety
safety:
	safety check -r requirements.txt --full-report

# Upload the package to the repository with twine
upload:
	twine upload dist/*

# Clean up build artifacts
clean:
	rm -rf build dist *.egg-info docs/_build
