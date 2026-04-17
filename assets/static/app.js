// DNS-RPZ Dashboard — Alpine.js component definitions + utilities
// Must be loaded BEFORE alpine.min.js (CSP build)

document.addEventListener('alpine:init', () => {
  // Dismissible alert banner (success / error flash)
  Alpine.data('alert', () => ({
    show: true,
    dismiss() { this.show = false },
  }))

  // User menu dropdown in topbar
  Alpine.data('userMenu', () => ({
    open: false,
    toggle() { this.open = !this.open },
    close() { this.open = false },
  }))
})

// ── Sidebar toggle ────────────────────────────────────────────────────
function isDesktop() { return window.innerWidth >= 1024 }

function openSidebar() {
  if (isDesktop()) {
    document.body.classList.remove('sidebar-closed')
  } else {
    document.body.classList.add('mobile-sidebar-open')
  }
}

function closeSidebar() {
  if (isDesktop()) {
    document.body.classList.add('sidebar-closed')
  } else {
    document.body.classList.remove('mobile-sidebar-open')
  }
}

function toggleSidebar() {
  if (isDesktop()) {
    document.body.classList.toggle('sidebar-closed')
  } else {
    document.body.classList.toggle('mobile-sidebar-open')
  }
}

document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeSidebar() })
// Close mobile sidebar on resize to desktop
window.addEventListener('resize', () => {
  if (isDesktop()) document.body.classList.remove('mobile-sidebar-open')
})

// Global confirm-before-submit handler (no Alpine/eval needed)
// Usage: add data-confirm="message" to any button.
//        Optionally add data-form-id="formId" to target a specific form.
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-confirm]')
  if (!btn) return
  if (!window.confirm(btn.dataset.confirm)) {
    e.preventDefault()
    e.stopPropagation()
    return
  }
  const formId = btn.dataset.formId
  if (formId) {
    e.preventDefault()
    document.getElementById(formId).submit()
  }
})
