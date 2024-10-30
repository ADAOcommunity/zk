# Contributing to Aiken ZKP Standards Library

Thank you for considering contributing to our Aiken ZKP Library! Your contributions help advance zero-knowledge proof capabilities on Cardano. Here are some guidelines to help you get started.

## How to Contribute

### Reporting Issues

If you encounter a bug or have a feature request, please open an issue on GitHub. When reporting issues:
- Provide a clear description of the problem
- Include steps to reproduce the issue
- Specify the version of the library you're using
- Share any relevant error messages or logs

### Contributing Code

1. **Fork the Repository**
   - Click the 'Fork' button at the top right of the repository page
   - This creates your own copy of the repository on GitHub

2. **Clone Your Fork**
   ```bash
   git clone [your-fork-url]
   cd aiken-zkp
   ```

3. **Create a Branch**
   ```bash
   git checkout -b feature-or-fix-description
   ```

4. **Make Changes**
   - Implement your changes
   - Follow our code style guidelines
   - Add tests for new functionality

5. **Commit Changes**
   ```bash
   git commit -m "Description of changes"
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature-or-fix-description
   ```

7. **Open a Pull Request**
   - Navigate to the original repository
   - Click "New Pull Request"
   - Select your fork and branch
   - Provide a detailed description of your changes

## Development Guidelines

### Code Style

- Follow existing code patterns and style
- Use meaningful variable and function names
- Comment complex logic or non-obvious implementations
- Keep functions focused and modular

### Testing Requirements

- Add tests for new functionality
- Ensure all existing tests pass
- Run the test suite using:
  ```bash
  aiken check
  ```

### Documentation

When contributing, please:
- Update README.md if adding new features
- Document new functions and types
- Include examples for new functionality

### ZKP Implementation Guidelines

When implementing or modifying ZKP systems:
- Maintain security guarantees
- Consider on-chain resource constraints
- Follow established cryptographic best practices
- Document any assumptions or limitations

## Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. We expect all participants to:
- Be respectful and considerate
- Welcome newcomers and support learning
- Focus on constructive feedback
- Maintain professional discourse

## Review Process

1. All submissions require review before merging
2. Reviewers will check for:
   - Correctness of ZKP implementations
   - Test coverage
   - Documentation completeness
   - Code style compliance
   - Performance considerations

## Questions?

If you have questions about contributing, please:
- Check existing documentation
- Review open and closed issues

Thank you for contributing to the Aiken ZKP Standards Library!
