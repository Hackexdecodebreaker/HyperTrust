// main.js — HyperTrust Client-Side Logic

// Auto-dismiss flash messages after 4 seconds
document.addEventListener('DOMContentLoaded', () => {
  // Flash dismissal
  document.querySelectorAll('.flash-msg').forEach(el => {
    el.addEventListener('click', () => {
      el.style.animation = 'slideIn 0.3s ease reverse forwards';
      setTimeout(() => el.remove(), 300);
    });
    setTimeout(() => {
      if (el.isConnected) {
        el.style.animation = 'slideIn 0.3s ease reverse forwards';
        setTimeout(() => el.remove(), 300);
      }
    }, 5000);
  });

  // Access request button loading state
  const accessBtn = document.getElementById('requestAccessBtn');
  if (accessBtn) {
    accessBtn.closest('form')?.addEventListener('submit', () => {
      accessBtn.disabled = true;
      accessBtn.innerHTML = '<span class="spinner"></span> Processing...';
      accessBtn.style.opacity = '0.8';
    });
  }

  // Active sidebar link highlighting
  const path = window.location.pathname;
  document.querySelectorAll('.sidebar-nav a').forEach(link => {
    if (link.getAttribute('href') === path) {
      link.classList.add('active');
    }
  });

  // Login/Register form toggle
  const showRegisterBtn = document.getElementById('show-register');
  const showLoginBtn = document.getElementById('show-login');
  const loginForm = document.querySelector('form[action*="login"]');
  const registerFormContainer = document.getElementById('register-form');

  if (showRegisterBtn && registerFormContainer) {
    showRegisterBtn.addEventListener('click', () => {
      loginForm.style.display = 'none';
      registerFormContainer.style.display = 'block';
      showRegisterBtn.style.display = 'none';
    });
  }

  if (showLoginBtn && registerFormContainer) {
    showLoginBtn.addEventListener('click', () => {
      registerFormContainer.style.display = 'none';
      loginForm.style.display = 'block';
      showRegisterBtn.style.display = 'inline-block';
    });
  }

  // Sidebar toggle functionality
  const sidebarToggle = document.getElementById('sidebarToggle');
  if (sidebarToggle) {
    // Check if sidebar should be hidden from localStorage
    const sidebarHidden = localStorage.getItem('sidebarHidden') === 'true';
    if (sidebarHidden) {
      document.body.classList.add('sidebar-hidden');
    }

    sidebarToggle.addEventListener('click', () => {
      document.body.classList.toggle('sidebar-hidden');
      const isHidden = document.body.classList.contains('sidebar-hidden');
      localStorage.setItem('sidebarHidden', isHidden);
    });
  }
});
