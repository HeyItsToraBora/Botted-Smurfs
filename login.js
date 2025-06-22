  // Check if user is already logged in
  async function checkAuth() {
    const accessTokenFromStorage = localStorage.getItem('accessToken');
    const accessTokenFromCookie = document.cookie.split('; ').find(row => row.startsWith('accessToken='))?.split('=')[1];
    
    const token = accessTokenFromStorage || accessTokenFromCookie;
    
    if (!token) {
        return false;
    }
    
    try {
        const response = await fetch('/verify-token', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                window.location.href = '/home.html';
                return true;
            }
        }
        
        // If token is invalid, clear it
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        document.cookie = 'accessToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        return false;
    } catch (error) {
        console.error('Auth check error:', error);
        return false;
    }
}

// Run auth check on page load
checkAuth();

// Set initial theme for login page
(function() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.body.setAttribute('data-theme', savedTheme);
    // Update emoji for initial load
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    if (themeToggleBtn) {
        themeToggleBtn.textContent = savedTheme === 'dark' ? '🌙' : '☀️';
    }
})();

// Theme toggle functionality
function toggleTheme() {
    const currentTheme = document.body.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    console.log('Theme toggled to:', newTheme);
    // Update emoji
    const btn = document.getElementById('themeToggleBtn');
    btn.textContent = newTheme === 'dark' ? '🌙' : '☀️';
    // Add animation
    btn.classList.add('animating');
    setTimeout(() => btn.classList.remove('animating'), 400);
}

// Password visibility toggle
function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password');
    const toggleButton = document.getElementById('passwordToggle');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleButton.textContent = '🔓';
    } else {
        passwordInput.type = 'password';
        toggleButton.textContent = '🔒';
    }
}

// Attach event listeners
document.getElementById('themeToggleBtn').addEventListener('click', toggleTheme);
document.getElementById('passwordToggle').addEventListener('click', togglePasswordVisibility);

// Form submission
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const remember = document.getElementById('remember').checked;

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password, remember })
        });

        const data = await response.json();

        if (data.success) {
            // Store the token in localStorage
            localStorage.setItem('accessToken', data.accessToken);
            if (data.refreshToken) {
                localStorage.setItem('refreshToken', data.refreshToken);
            }
            window.location.href = data.redirect || '/home.html';
        } else {
            document.getElementById('errorMessage').textContent = data.message;
            document.getElementById('errorMessage').style.display = 'block';
        }
    } catch (error) {
        console.error('Login error:', error);
        document.getElementById('errorMessage').textContent = 'An error occurred during login';
        document.getElementById('errorMessage').style.display = 'block';
    }
});

async function loadAccounts() {
    try {
        const response = await fetch('/accounts', {
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            }
        });
        const data = await response.json();
        
        if (data.success) {
            const accountsList = document.getElementById('accountsList');
            accountsList.innerHTML = '';
            
            data.accounts.forEach(account => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${account.username}</td>
                    <td>${account.email}</td>
                    <td>${account.discord_username || ''}${account.discord_id ? ` (${account.discord_id})` : ''}</td>
                    <td class="status-${account.status}">${account.status}</td>
                    <td>${account.is_admin ? 'Yes' : 'No'}</td>
                    <td>${new Date(account.created_at).toLocaleString()}</td>
                    <td class="action-buttons">
                        <button onclick="toggleStatus('${account.id}', '${account.status}')" 
                                class="${account.status === 'active' ? 'btn-ban' : ''}">
                            ${account.status === 'active' ? 'Ban' : 'Activate'}
                        </button>
                        ${account.status === 'banned' ? 
                            `<button onclick="showBanReason('${account.id}')">View Ban Reason</button>` : 
                            ''}
                    </td>
                `;
                accountsList.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading accounts:', error);
    }
}