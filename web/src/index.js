const CryptoJS = require('crypto-js');

const SHA1_PATTERN = /^[a-fA-F0-9]{40}$/;

/**
 * Accept either a SHA1 hash or a plain password and return the hash to send.
 * Only the hash ever leaves the browser.
 */
function toSha1Hash(value) {
    if (SHA1_PATTERN.test(value)) {
        return value;
    }
    return CryptoJS.SHA1(value).toString();
}

/**
 * Turn an /api/check/hash payload into the message and CSS class to display.
 */
function resultFor(data) {
    if (data.error) {
        return { message: `Error: ${data.error}`, type: 'error' };
    }
    if (data.found) {
        return {
            message: `⚠️ Warning: This password has been found in ${data.count} data breaches!`,
            type: 'warning',
        };
    }
    return {
        message: '✓ Good news: This password has not been found in any known data breaches.',
        type: 'success',
    };
}

function wireUp() {
    // Get DOM elements
    const form = document.getElementById('checkerForm');
    const passwordInput = document.getElementById('password');
    const togglePasswordBtn = document.getElementById('togglePassword');
    const resultDiv = document.getElementById('result');
    const loadingDiv = document.getElementById('loading');

    function showResult(message, type) {
        resultDiv.textContent = message;
        resultDiv.className = `result show ${type}`;
    }

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
            const hash = toSha1Hash(passwordValue);

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

            const { message, type } = resultFor(await response.json());
            showResult(message, type);
        } catch (error) {
            loadingDiv.classList.remove('show');
            showResult(`Error: ${error.message}`, 'error');
        }
    }

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

    return { checkPassword, showResult };
}

// Guarded so the module can be required by the tests, which have no page.
if (typeof document !== 'undefined' && document.getElementById('checkerForm')) {
    wireUp();
}

module.exports = { toSha1Hash, resultFor, wireUp, SHA1_PATTERN };
