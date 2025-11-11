const CryptoJS = require('crypto-js');

// Get DOM elements
const form = document.getElementById('checkerForm');
const passwordInput = document.getElementById('password');
const togglePasswordBtn = document.getElementById('togglePassword');
const resultDiv = document.getElementById('result');
const loadingDiv = document.getElementById('loading');

// Handle form submission
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await checkPassword();
});

// Handle password visibility toggle
togglePasswordBtn.addEventListener('click', (e) => {
    e.preventDefault();
    const type = passwordInput.getAttribute('type');
    if (type === 'password') {
        passwordInput.setAttribute('type', 'text');
        togglePasswordBtn.classList.add('showing');
    } else {
        passwordInput.setAttribute('type', 'password');
        togglePasswordBtn.classList.remove('showing');
    }
});

/**
 * Submit function that calls /api/check/hash
 * Accepts either a SHA1 hash or a plain password
 */
async function checkPassword() {
    const passwordValue = passwordInput.value.trim();

    if (!passwordValue) {
        showResult('Please enter a password or SHA1 hash', 'error');
        return;
    }

    // Show loading state
    loadingDiv.classList.add('show');
    resultDiv.classList.remove('show');

    try {
        // Check if input looks like a SHA1 hash (40 hex characters)
        let hash;
        if (/^[a-fA-F0-9]{40}$/.test(passwordValue)) {
            // Already a SHA1 hash
            hash = passwordValue;
        } else {
            // Hash the password using SHA1
            hash = CryptoJS.SHA1(passwordValue).toString();
        }

        // Call the API endpoint
        const response = await fetch('/api/check/hash', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ hash }),
        });

        loadingDiv.classList.remove('show');

        if (!response.ok) {
            const errorText = await response.text();
            showResult(`Error: ${errorText}`, 'error');
            return;
        }

        const data = await response.json();

        if (data.error) {
            showResult(`Error: ${data.error}`, 'error');
        } else if (data.found) {
            showResult(
                `⚠️ Warning: This password has been found in ${data.count} data breaches!`,
                'warning'
            );
        } else {
            showResult(
                `✓ Good news: This password has not been found in any known data breaches.`,
                'success'
            );
        }
    } catch (error) {
        loadingDiv.classList.remove('show');
        showResult(`Error: ${error.message}`, 'error');
    }
}

function showResult(message, type) {
    resultDiv.textContent = message;
    resultDiv.className = `result show ${type}`;
}
