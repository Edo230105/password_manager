# 🔐 Secure Password Manager

A comprehensive password manager with MFA support, browser extension integration, and cross-platform compatibility.

## Features

- 🔒 **Encrypted Storage**: AES-256 encryption with PBKDF2 key derivation
- 🔑 **MFA Support**: TOTP code generation (Google Authenticator compatible)
- 🌐 **Browser Extension**: Auto-fill functionality for Chrome/Firefox
- 🔍 **Search & Filter**: Quick password lookup
- 📱 **Cross-Platform**: Works on Windows, macOS, and Linux
- 💾 **Import/Export**: CSV and JSON support
- 🔄 **Backup System**: Automatic and manual backups
- 🎲 **Password Generator**: Secure password and passphrase generation

## Quick Start

### 1. Clone the Repository
\`\`\`bash
git clone https://github.com/Edo230105/password_manager.git
cd password-manager
\`\`\`

### 2. Install Dependencies
\`\`\`bash
pip install -r requirements.txt
\`\`\`

### 3. Run the Application
\`\`\`bash
python password_manager.py
\`\`\`

### 4. First Time Setup
- Create a master password when prompted
- Start adding your passwords securely

## Browser Extension Setup

### Chrome/Edge Installation
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked" and select the `browser-extension` folder
4. The extension icon will appear in your toolbar

### Firefox Installation
1. Open Firefox and go to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select the `manifest.json` file from the `browser-extension` folder

## Project Structure

\`\`\`
password-manager/
├── password_manager.py          # Main application
├── enhanced_password_manager.py # Enhanced version with web server
├── browser-extension/           # Browser extension files
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── content.js
│   ├── background.js
│   └── settings.html
├── requirements.txt             # Python dependencies
├── README.md                   # This file
├── .gitignore                  # Git ignore rules
└── LICENSE                     # MIT License
\`\`\`

## Usage

### Basic Operations
- **Add Password**: Click "Add Password" button
- **Search**: Type in the search box to filter passwords
- **Copy Password**: Right-click on entry → "Copy Password"
- **Copy MFA Code**: Right-click on entry → "Copy MFA Code"
- **View Details**: Double-click on any entry

### Browser Extension
- **Auto-fill**: Click extension icon and select password
- **Quick Access**: Right-click on password fields
- **Smart Matching**: Extension suggests passwords based on website domain

### Security Features
- **Master Password**: Required for all operations
- **Encryption**: All data encrypted with AES-256
- **Local Storage**: No cloud dependencies
- **Auto-lock**: Session expires when application closes

## Development

### Running Tests
\`\`\`bash
python -m pytest tests/
\`\`\`

### Building for Distribution
\`\`\`bash
python setup.py build
\`\`\`

### Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

- **Master Password**: Choose a strong, unique master password
- **Backup**: Regularly backup your password database
- **Updates**: Keep the application updated for security patches
- **Environment**: Run only on trusted devices

## Troubleshooting

### Common Issues

**"Failed to start web server"**
- Check if port 8765 is available
- Run as administrator if needed
- Check firewall settings

**"Cannot connect to Password Manager"**
- Ensure the desktop app is running
- Verify the web server started successfully
- Check browser extension settings

**"Invalid master password"**
- Ensure caps lock is off
- Try typing the password in a text editor first
- Reset database if password is forgotten (data will be lost)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue on GitHub or contact [your-email@example.com].

## Changelog

### v1.0.0
- Initial release with basic password management
- MFA support with TOTP codes
- Browser extension integration
- Import/export functionality
- Backup and restore features
\`\`\`

```txt file=".gitignore"
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual Environment
venv/
env/
ENV/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Database files
*.db
*.sqlite
*.sqlite3

# Backup files
backups/
*.backup

# Logs
*.log
logs/

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Temporary files
*.tmp
*.temp
temp/

# Configuration files with sensitive data
config.ini
settings.json
.env

# Test files
.pytest_cache/
.coverage
htmlcov/

# Distribution
*.tar.gz
*.zip
