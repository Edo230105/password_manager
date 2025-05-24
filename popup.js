class PasswordManagerPopup {
  constructor() {
    this.apiUrl = "http://localhost:8765"
    this.passwords = []
    this.currentTab = null
    this.init()
  }

  async init() {
    await this.getCurrentTab()
    this.setupEventListeners()
    await this.checkConnection()
    await this.loadPasswords()
  }

  async getCurrentTab() {
    const [tab] = await window.chrome.tabs.query({ active: true, currentWindow: true })
    this.currentTab = tab
  }

  setupEventListeners() {
    const searchInput = document.getElementById("searchInput")
    const settingsBtn = document.getElementById("settingsBtn")

    searchInput.addEventListener("input", (e) => {
      this.filterPasswords(e.target.value)
    })

    settingsBtn.addEventListener("click", () => {
      this.openSettings()
    })
  }

  async checkConnection() {
    const statusEl = document.getElementById("status")
    const statusTextEl = document.getElementById("statusText")

    try {
      const response = await fetch(`${this.apiUrl}/status`, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      })

      if (response.ok) {
        statusEl.className = "status connected"
        statusTextEl.textContent = "Connected to Password Manager"
      } else {
        throw new Error("Connection failed")
      }
    } catch (error) {
      statusEl.className = "status disconnected"
      statusTextEl.textContent = "Disconnected - Start Password Manager"
      this.showError("Cannot connect to Password Manager. Please ensure the desktop app is running.")
    }
  }

  async loadPasswords() {
    try {
      const response = await fetch(`${this.apiUrl}/passwords`, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      })

      if (response.ok) {
        const data = await response.json()
        this.passwords = data.passwords || []
        this.renderPasswords()
      } else {
        throw new Error("Failed to load passwords")
      }
    } catch (error) {
      this.showError("Failed to load passwords from desktop app.")
      this.renderEmptyState()
    }
  }

  filterPasswords(query) {
    const filtered = this.passwords.filter(
      (pwd) =>
        pwd.service.toLowerCase().includes(query.toLowerCase()) ||
        pwd.username.toLowerCase().includes(query.toLowerCase()),
    )
    this.renderPasswords(filtered)
  }

  renderPasswords(passwordsToRender = this.passwords) {
    const listEl = document.getElementById("passwordList")

    if (passwordsToRender.length === 0) {
      this.renderEmptyState()
      return
    }

    listEl.innerHTML = passwordsToRender
      .map(
        (pwd) => `
            <div class="password-item" data-id="${pwd.id}">
                <div class="password-service">${this.escapeHtml(pwd.service)}</div>
                <div class="password-username">${this.escapeHtml(pwd.username)}</div>
                <div class="password-actions">
                    <button class="btn btn-primary" onclick="passwordManager.fillPassword(${pwd.id})">
                        Auto-fill
                    </button>
                    <button class="btn btn-secondary" onclick="passwordManager.copyPassword(${pwd.id})">
                        Copy
                    </button>
                    ${
                      pwd.mfa_secret
                        ? `
                        <button class="btn btn-secondary" onclick="passwordManager.copyMFA(${pwd.id})">
                            Copy MFA
                        </button>
                    `
                        : ""
                    }
                </div>
            </div>
        `,
      )
      .join("")
  }

  renderEmptyState() {
    const listEl = document.getElementById("passwordList")
    listEl.innerHTML = `
            <div class="empty-state">
                <div>No passwords found</div>
                <div style="font-size: 12px; margin-top: 8px;">
                    Add passwords in the desktop app
                </div>
            </div>
        `
  }

  async fillPassword(passwordId) {
    try {
      const password = this.passwords.find((p) => p.id === passwordId)
      if (!password) return

      // Send message to content script to fill the form
      await window.chrome.tabs.sendMessage(this.currentTab.id, {
        action: "fillPassword",
        data: {
          username: password.username,
          password: password.password,
          service: password.service,
        },
      })

      // Close popup after filling
      window.close()
    } catch (error) {
      this.showError("Failed to auto-fill password. Please try again.")
    }
  }

  async copyPassword(passwordId) {
    try {
      const password = this.passwords.find((p) => p.id === passwordId)
      if (!password) return

      await navigator.clipboard.writeText(password.password)
      this.showSuccess("Password copied to clipboard!")
    } catch (error) {
      this.showError("Failed to copy password.")
    }
  }

  async copyMFA(passwordId) {
    try {
      const response = await fetch(`${this.apiUrl}/mfa/${passwordId}`, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      })

      if (response.ok) {
        const data = await response.json()
        await navigator.clipboard.writeText(data.code)
        this.showSuccess("MFA code copied to clipboard!")
      } else {
        throw new Error("Failed to get MFA code")
      }
    } catch (error) {
      this.showError("Failed to copy MFA code.")
    }
  }

  showError(message) {
    const errorEl = document.getElementById("error")
    errorEl.textContent = message
    errorEl.style.display = "block"
    setTimeout(() => {
      errorEl.style.display = "none"
    }, 5000)
  }

  showSuccess(message) {
    // Create temporary success message
    const successEl = document.createElement("div")
    successEl.className = "status connected"
    successEl.style.marginBottom = "15px"
    successEl.innerHTML = `<div class="status-dot"></div><span>${message}</span>`

    const errorEl = document.getElementById("error")
    errorEl.parentNode.insertBefore(successEl, errorEl)

    setTimeout(() => {
      successEl.remove()
    }, 3000)
  }

  openSettings() {
    window.chrome.tabs.create({ url: window.chrome.runtime.getURL("settings.html") })
  }

  escapeHtml(text) {
    const div = document.createElement("div")
    div.textContent = text
    return div.innerHTML
  }
}

// Initialize popup
const passwordManager = new PasswordManagerPopup()
