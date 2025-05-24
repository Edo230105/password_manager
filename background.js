// Declare the chrome variable to fix lint/correctness/noUndeclaredVariables error
const chrome = window.chrome

class BackgroundManager {
  constructor() {
    this.init()
  }

  init() {
    this.setupContextMenus()
    this.setupMessageHandlers()
    this.checkDesktopAppConnection()
  }

  setupContextMenus() {
    chrome.runtime.onInstalled.addListener(() => {
      chrome.contextMenus.create({
        id: "fillPassword",
        title: "Fill password with Password Manager",
        contexts: ["editable"],
      })

      chrome.contextMenus.create({
        id: "generatePassword",
        title: "Generate new password",
        contexts: ["editable"],
      })
    })

    chrome.contextMenus.onClicked.addListener((info, tab) => {
      if (info.menuItemId === "fillPassword") {
        this.handleFillPassword(tab)
      } else if (info.menuItemId === "generatePassword") {
        this.handleGeneratePassword(tab)
      }
    })
  }

  setupMessageHandlers() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === "getPasswords") {
        this.getPasswordsFromDesktop().then(sendResponse)
        return true
      }
    })
  }

  async checkDesktopAppConnection() {
    try {
      const response = await fetch("http://localhost:8765/status")
      if (response.ok) {
        chrome.action.setBadgeText({ text: "✓" })
        chrome.action.setBadgeBackgroundColor({ color: "#28a745" })
      } else {
        throw new Error("Connection failed")
      }
    } catch (error) {
      chrome.action.setBadgeText({ text: "!" })
      chrome.action.setBadgeBackgroundColor({ color: "#dc3545" })
    }

    // Check every 30 seconds
    setTimeout(() => this.checkDesktopAppConnection(), 30000)
  }

  async handleFillPassword(tab) {
    try {
      const passwords = await this.getPasswordsFromDesktop()
      const currentDomain = new URL(tab.url).hostname

      const matchingPasswords = passwords.filter(
        (pwd) =>
          pwd.service.toLowerCase().includes(currentDomain.toLowerCase()) ||
          currentDomain.includes(pwd.service.toLowerCase()),
      )

      if (matchingPasswords.length === 1) {
        chrome.tabs.sendMessage(tab.id, {
          action: "fillPassword",
          data: matchingPasswords[0],
        })
      } else {
        // Open popup for selection
        chrome.action.openPopup()
      }
    } catch (error) {
      console.error("Failed to fill password:", error)
    }
  }

  async handleGeneratePassword(tab) {
    try {
      const response = await fetch("http://localhost:8765/generate-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ length: 16, symbols: true }),
      })

      if (response.ok) {
        const data = await response.json()
        chrome.tabs.sendMessage(tab.id, {
          action: "insertPassword",
          data: { password: data.password },
        })
      }
    } catch (error) {
      console.error("Failed to generate password:", error)
    }
  }

  async getPasswordsFromDesktop() {
    const response = await fetch("http://localhost:8765/passwords")
    const data = await response.json()
    return data.passwords || []
  }
}

// Initialize background manager
new BackgroundManager()
