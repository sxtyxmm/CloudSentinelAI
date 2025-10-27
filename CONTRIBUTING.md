# Contributing to CloudSentinelAI

Thank you for your interest in contributing to CloudSentinelAI! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Python version, etc.)
- Relevant logs or screenshots

### Suggesting Features

We welcome feature suggestions! Please create an issue with:
- Clear description of the feature
- Use case and benefits
- Example implementation (if applicable)

### Pull Requests

1. **Fork the repository**
   ```bash
   git clone https://github.com/sxtyxmm/CloudSentinelAI.git
   cd CloudSentinelAI
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Test your changes**
   ```bash
   # Backend tests
   cd backend
   pytest
   
   # Frontend tests
   cd frontend
   npm test
   ```

5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```

7. **Create a Pull Request**
   - Provide a clear description
   - Reference any related issues
   - Include screenshots for UI changes

## Development Setup

### Backend Development

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev
```

### Running with Docker

```bash
docker-compose up -d
```

## Code Style

### Python (Backend)
- Follow PEP 8 style guide
- Use type hints
- Write docstrings for functions and classes
- Maximum line length: 100 characters

Example:
```python
def process_log(log_data: Dict[str, Any]) -> Optional[ThreatAlert]:
    """
    Process a single log entry and detect threats.
    
    Args:
        log_data: Raw log data from cloud provider
        
    Returns:
        ThreatAlert if threat detected, None otherwise
    """
    pass
```

### TypeScript (Frontend)
- Use TypeScript for type safety
- Follow React best practices
- Use functional components with hooks
- Keep components focused and reusable

Example:
```typescript
interface AlertsListProps {
  alerts: Alert[];
  onAlertClick?: (alert: Alert) => void;
}

export const AlertsList: React.FC<AlertsListProps> = ({ alerts, onAlertClick }) => {
  // Component implementation
};
```

## Testing Guidelines

### Backend Tests
- Write unit tests for business logic
- Use pytest fixtures for test data
- Mock external API calls
- Aim for >80% code coverage

### Frontend Tests
- Test component rendering
- Test user interactions
- Mock API responses
- Use React Testing Library

## Commit Message Guidelines

Use clear, descriptive commit messages:

```
feat: Add IP reputation checking with VirusTotal
fix: Resolve database connection timeout issue
docs: Update API documentation for alerts endpoint
test: Add tests for anomaly detection algorithm
refactor: Improve log processing performance
```

Prefixes:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `style`: Code style changes
- `chore`: Maintenance tasks

## Documentation

When adding new features:
1. Update relevant documentation files
2. Add API documentation if adding endpoints
3. Update README if changing setup process
4. Add inline code comments for complex logic

## Questions?

If you have questions:
- Check existing documentation
- Search existing issues
- Create a new issue with your question

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the best solution for the project
- Help others learn and grow

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to CloudSentinelAI! 🚀
