.PHONY: clean build test docs upload

# Install dependencies for development
dev:
	pip install -r dev-requirements.txt

# Install dependencies for production
prod:
	pip install -r requirements.txt

# Format code with black
black:
	black src

# Run pylint linter
pylint:
	pylint -d duplicate-code src

# Build documentation with sphinx
docs:
	sphinx-build -b html docs/source docs/_build

# Build the python package
build:
	python setup.py sdist bdist_wheel

# Run tests with pytest
test:
	pytest

# Run security checks with bandit
bandit:
	bandit -c pyproject.toml -r .

# Upload the package to the repository with twine
upload:
	twine upload dist/*

# Clean up build artifacts
clean:
	rm -rf build dist *.egg-info docs/_build
