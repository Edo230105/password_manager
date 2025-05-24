// Declare chrome variable
const chrome = window.chrome

class AutoFillManager {
  constructor() {
    this.init()
  }

  init() {
    this.setupMessageListener()
    this.detectForms()
    this.addAutoFillButtons()
  }

  setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === "fillPassword") {
        this.fillForm(message.data)
        sendResponse({ success: true })
      }
      return true
    })
  }

  detectForms() {
    // Detect login forms on the page
    const forms = document.querySelectorAll("form")
    forms.forEach((form) => {
      const usernameField = this.findUsernameField(form)
      const passwordField = this.findPasswordField(form)

      if (usernameField && passwordField) {
        this.markAsLoginForm(form)
      }
    })
  }

  findUsernameField(form) {
    const selectors = [
      'input[type="email"]',
      'input[type="text"][name*="user"]',
      'input[type="text"][name*="email"]',
      'input[type="text"][id*="user"]',
      'input[type="text"][id*="email"]',
      'input[type="text"][placeholder*="email"]',
      'input[type="text"][placeholder*="username"]',
      'input[autocomplete="username"]',
      'input[autocomplete="email"]',
    ]

    for (const selector of selectors) {
      const field = form.querySelector(selector)
      if (field) return field
    }

    // Fallback: first text input
    return form.querySelector('input[type="text"]')
  }

  findPasswordField(form) {
    return form.querySelector('input[type="password"]')
  }

  markAsLoginForm(form) {
    form.setAttribute("data-pm-login-form", "true")
  }

  addAutoFillButtons() {
    const loginForms = document.querySelectorAll('form[data-pm-login-form="true"]')

    loginForms.forEach((form) => {
      const passwordField = this.findPasswordField(form)
      if (passwordField && !passwordField.nextElementSibling?.classList.contains("pm-autofill-btn")) {
        this.addAutoFillButton(passwordField)
      }
    })
  }

  addAutoFillButton(passwordField) {
    const button = document.createElement("button")
    button.type = "button"
    button.className = "pm-autofill-btn"
    button.innerHTML = "🔐"
    button.title = "Auto-fill with Password Manager"
    button.style.cssText = `
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            background: #007bff;
            color: white;
            border: none;
            border-radius: 3px;
            width: 24px;
            height: 24px;
            font-size: 12px;
            cursor: pointer;
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
        `

    // Make password field container relative
    const container = passwordField.parentElement
    if (getComputedStyle(container).position === "static") {
      container.style.position = "relative"
    }

    button.addEventListener("click", () => {
      this.showPasswordSelector()
    })

    container.appendChild(button)
  }

  async showPasswordSelector() {
    try {
      const response = await fetch("http://localhost:8765/passwords")
      const data = await response.json()
      const passwords = data.passwords || []

      const currentDomain = window.location.hostname
      const matchingPasswords = passwords.filter(
        (pwd) =>
          pwd.service.toLowerCase().includes(currentDomain.toLowerCase()) ||
          currentDomain.includes(pwd.service.toLowerCase()),
      )

      if (matchingPasswords.length === 1) {
        // Auto-fill if only one match
        this.fillForm(matchingPasswords[0])
      } else if (matchingPasswords.length > 1) {
        // Show selector for multiple matches
        this.showPasswordMenu(matchingPasswords)
      } else {
        // Show all passwords if no matches
        this.showPasswordMenu(passwords)
      }
    } catch (error) {
      this.showNotification("Cannot connect to Password Manager", "error")
    }
  }

  showPasswordMenu(passwords) {
    // Remove existing menu
    const existingMenu = document.getElementById("pm-password-menu")
    if (existingMenu) {
      existingMenu.remove()
    }

    const menu = document.createElement("div")
    menu.id = "pm-password-menu"
    menu.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            border: 1px solid #ccc;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10001;
            max-width: 400px;
            max-height: 300px;
            overflow-y: auto;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        `

    const header = document.createElement("div")
    header.style.cssText = `
            padding: 16px;
            border-bottom: 1px solid #eee;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        `
    header.innerHTML = `
            <span>Select Password</span>
            <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; font-size: 18px; cursor: pointer;">×</button>
        `

    menu.appendChild(header)

    passwords.forEach((pwd) => {
      const item = document.createElement("div")
      item.style.cssText = `
                padding: 12px 16px;
                border-bottom: 1px solid #f0f0f0;
                cursor: pointer;
                transition: background-color 0.2s;
            `
      item.innerHTML = `
                <div style="font-weight: 500; margin-bottom: 4px;">${this.escapeHtml(pwd.service)}</div>
                <div style="font-size: 12px; color: #666;">${this.escapeHtml(pwd.username)}</div>
            `

      item.addEventListener("mouseenter", () => {
        item.style.backgroundColor = "#f8f9fa"
      })

      item.addEventListener("mouseleave", () => {
        item.style.backgroundColor = "white"
      })

      item.addEventListener("click", () => {
        this.fillForm(pwd)
        menu.remove()
      })

      menu.appendChild(item)
    })

    document.body.appendChild(menu)

    // Close menu when clicking outside
    setTimeout(() => {
      document.addEventListener(
        "click",
        (e) => {
          if (!menu.contains(e.target)) {
            menu.remove()
          }
        },
        { once: true },
      )
    }, 100)
  }

  fillForm(passwordData) {
    const forms = document.querySelectorAll('form[data-pm-login-form="true"]')

    for (const form of forms) {
      const usernameField = this.findUsernameField(form)
      const passwordField = this.findPasswordField(form)

      if (usernameField && passwordField) {
        // Fill username
        this.fillField(usernameField, passwordData.username)

        // Fill password
        this.fillField(passwordField, passwordData.password)

        this.showNotification(`Auto-filled credentials for ${passwordData.service}`, "success")
        break
      }
    }
  }

  fillField(field, value) {
    // Set value
    field.value = value

    // Trigger events to ensure the form recognizes the change
    const events = ["input", "change", "keyup", "keydown"]
    events.forEach((eventType) => {
      const event = new Event(eventType, { bubbles: true })
      field.dispatchEvent(event)
    })

    // For React/Vue apps
    const reactEvent = new Event("input", { bubbles: true })
    Object.defineProperty(reactEvent, "target", { value: field })
    field.dispatchEvent(reactEvent)
  }

  showNotification(message, type = "info") {
    // Remove existing notification
    const existing = document.getElementById("pm-notification")
    if (existing) {
      existing.remove()
    }

    const notification = document.createElement("div")
    notification.id = "pm-notification"
    notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === "error" ? "#dc3545" : "#28a745"};
            color: white;
            padding: 12px 16px;
            border-radius: 4px;
            z-index: 10002;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            max-width: 300px;
        `
    notification.textContent = message

    document.body.appendChild(notification)

    setTimeout(() => {
      notification.remove()
    }, 3000)
  }

  escapeHtml(text) {
    const div = document.createElement("div")
    div.textContent = text
    return div.innerHTML
  }
}

// Initialize auto-fill manager
const autoFillManager = new AutoFillManager()

// Re-run detection when DOM changes (for SPAs)
const observer = new MutationObserver(() => {
  autoFillManager.detectForms()
  autoFillManager.addAutoFillButtons()
})

observer.observe(document.body, {
  childList: true,
  subtree: true,
})
