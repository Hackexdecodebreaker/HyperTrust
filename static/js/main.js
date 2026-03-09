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
});
