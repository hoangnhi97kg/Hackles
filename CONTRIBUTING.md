# Contributing to Hackles

Thank you for your interest in contributing to Hackles! This document provides guidelines for contributing to the project.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Real-Fruit-Snacks/hackles.git
   cd hackles
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   .\venv\Scripts\activate   # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. Run tests to verify setup:
   ```bash
   pytest tests/
   ```

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines
- Use type hints for function signatures
- Keep lines under 100 characters
- Use descriptive variable and function names

## Adding New Queries

1. Create a new file in the appropriate category folder under `hackles/queries/`
2. Use the `@register_query` decorator:
   ```python
   @register_query(
       name="Query Name",
       category="Category",
       default=True,
       severity=Severity.HIGH
   )
   def get_query_name(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
       """Query docstring"""
       # Implementation
       return result_count
   ```
3. Follow the existing patterns in similar query files
4. Add abuse templates to `hackles/abuse/templates/` if applicable

### Non-Admin Query Guidelines

When writing queries that filter for "non-admin" principals, always include RID-based exclusions. The `admincount` property alone is unreliable as it can be NULL or false for built-in admin groups.

**Required exclusions for non-admin ACL queries:**
```cypher
WHERE (n.admincount IS NULL OR n.admincount = false)
AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
AND NOT n.objectid ENDS WITH '-544'  // Administrators
AND NOT n.objectid ENDS WITH '-548'  // Account Operators
AND NOT n.objectid ENDS WITH '-549'  // Server Operators
AND NOT n.objectid ENDS WITH '-550'  // Print Operators
AND NOT n.objectid ENDS WITH '-551'  // Backup Operators
```

See `CLAUDE.md` for the full reference of well-known RIDs and additional exclusion patterns.

## Adding Abuse Templates

Create a YAML file in `hackles/abuse/templates/`:

```yaml
name: AttackName
description: Brief description of the attack
commands:
  - tool: ToolName
    command: "command with <PLACEHOLDER> values"
    description: What this command does
opsec:
  - Security consideration
references:
  - https://example.com/reference
```

## Branch Naming Conventions

Use descriptive branch names with these prefixes:
- `feature/` - New features (e.g., `feature/add-azure-queries`)
- `fix/` - Bug fixes (e.g., `fix/cypher-syntax-error`)
- `docs/` - Documentation updates (e.g., `docs/update-readme`)
- `refactor/` - Code refactoring (e.g., `refactor/query-registry`)
- `test/` - Test additions or fixes (e.g., `test/add-cli-tests`)

## Commit Message Guidelines

Write clear, descriptive commit messages:

**Format:**
```
<type>: <short summary>

<optional detailed description>
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Test additions or changes
- `chore:` - Maintenance tasks

**Examples:**
```
feat: Add ESC16 ADCS vulnerability query

fix: Resolve Cypher syntax error in delegation query

docs: Update README with new CLI options
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest tests/`
5. Commit with a descriptive message
6. Push to your fork
7. Open a Pull Request

## Testing

- Write tests for new functionality
- Ensure existing tests pass
- Run the test suite:
  ```bash
  pytest tests/ -v
  pytest tests/ --cov=hackles --cov-report=html  # With coverage
  ```

## Reporting Issues

When reporting issues, please include:
- Python version
- Operating system
- BloodHound CE version
- Steps to reproduce
- Expected vs actual behavior
- Relevant error messages

## Questions?

Open an issue for questions or discussion about potential contributions.
