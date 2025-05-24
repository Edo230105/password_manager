// Declare chrome variable or import it if necessary
const chrome = window.chrome

class SettingsManager {
  constructor() {
    this.init()
  }

  async init() {
    await this.loadSettings()
    this.checkConnection()
    this.setupEventListeners()
  }

  async loadSettings() {
    const settings = await chrome.storage.sync.get({
      port: 8765,
      autofillBehavior: "auto",
      clearClipboard: true,
    })

    document.getElementById("portInput").value = settings.port
    document.getElementById("autofillBehavior").value = settings.autofillBehavior
    document.getElementById("clearClipboard").checked = settings.clearClipboard
  }

  async saveSettings() {
    const settings = {
      port: Number.parseInt(document.getElementById("portInput").value),
      autofillBehavior: document.getElementById("autofillBehavior").value,
      clearClipboard: document.getElementById("clearClipboard").checked,
    }

    await chrome.storage.sync.set(settings)

    // Show success message
    const btn = document.querySelector(".btn")
    const originalText = btn.textContent
    btn.textContent = "Settings Saved!"
    btn.style.background = "#28a745"

    setTimeout(() => {
      btn.textContent = originalText
      btn.style.background = "#007bff"
    }, 2000)
  }

  async checkConnection() {
    const statusEl = document.getElementById("connectionStatus")
    const settings = await chrome.storage.sync.get({ port: 8765 })

    try {
      const response = await fetch(`http://localhost:${settings.port}/status`)
      if (response.ok) {
        statusEl.innerHTML = `
                    <span class="status-indicator status-connected"></span>
                    Connected to Password Manager
                `
      } else {
        throw new Error("Connection failed")
      }
    } catch (error) {
      statusEl.innerHTML = `
                <span class="status-indicator status-disconnected"></span>
                Disconnected - Please start the desktop app
            `
    }
  }

  setupEventListeners() {
    document.getElementById("portInput").addEventListener("change", () => {
      setTimeout(() => this.checkConnection(), 500)
    })
  }
}

// Global function for button
async function saveSettings() {
  await settingsManager.saveSettings()
}

// Initialize settings
const settingsManager = new SettingsManager()
