/* JPG Law — main.js */

// Mobile nav toggle
const toggle = document.querySelector('.nav-mobile-toggle');
const mobileNav = document.querySelector('.mobile-nav');

if (toggle && mobileNav) {
  toggle.addEventListener('click', () => {
    const open = mobileNav.classList.toggle('is-open');
    toggle.textContent = open ? '✕' : '☰';
    document.body.style.overflow = open ? 'hidden' : '';
  });
}

// Mark active nav link
const path = window.location.pathname;
document.querySelectorAll('.nav-links a, .dropdown a').forEach(a => {
  const href = a.getAttribute('href');
  if (href && href !== '/' && path.startsWith(href)) {
    a.classList.add('active');
  } else if (href === '/' && path === '/') {
    a.classList.add('active');
  }
});

// Close mobile nav on link click
document.querySelectorAll('.mobile-nav a').forEach(a => {
  a.addEventListener('click', () => {
    mobileNav.classList.remove('is-open');
    if (toggle) toggle.textContent = '☰';
    document.body.style.overflow = '';
  });
});

// Nav shadow on scroll
const nav = document.querySelector('.nav');
if (nav) {
  window.addEventListener('scroll', () => {
    nav.style.boxShadow = window.scrollY > 10
      ? '0 2px 16px rgba(15,31,54,0.10)'
      : 'none';
  }, { passive: true });
}
