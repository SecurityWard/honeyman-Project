// SecureTech Industries Portal JavaScript
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const loginBtn = document.querySelector('.login-btn');
    
    // Form submission handler
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember').checked;
        
        // Show loading state
        loginBtn.innerHTML = '<span class="loading"></span> Authenticating...';
        loginBtn.disabled = true;
        
        // Log the credential attempt (honeypot function)
        logCredentialAttempt(username, password, remember);
        
        // Simulate authentication delay
        setTimeout(function() {
            // Always show "invalid credentials" to maintain honeypot
            showError('Invalid username or password. Please check your credentials and try again.');
            resetLoginForm();
        }, 2000 + Math.random() * 3000); // Random delay 2-5 seconds
    });
    
    function logCredentialAttempt(username, password, remember) {
        // Send credential attempt to honeypot logging system
        const attemptData = {
            timestamp: new Date().toISOString(),
            source_ip: getClientIP(),
            user_agent: navigator.userAgent,
            username: username,
            password: password,
            remember_me: remember,
            page: 'login',
            service: 'web_portal'
        };
        
        // Send to backend logging (this will be caught by OpenCanary)\n        fetch('/api/login-attempt', {\n            method: 'POST',\n            headers: {\n                'Content-Type': 'application/json'\n            },\n            body: JSON.stringify(attemptData)\n        }).catch(function(error) {\n            console.log('Logging service unavailable');\n        });\n    }\n    \n    function showError(message) {\n        // Remove existing error messages\n        const existingError = document.querySelector('.error-message');\n        if (existingError) {\n            existingError.remove();\n        }\n        \n        // Create error message\n        const errorDiv = document.createElement('div');\n        errorDiv.className = 'error-message';\n        errorDiv.style.cssText = `\n            background: #f8d7da;\n            color: #721c24;\n            padding: 1rem;\n            border-radius: 8px;\n            margin-bottom: 1rem;\n            border: 1px solid #f5c6cb;\n            text-align: center;\n        `;\n        errorDiv.textContent = message;\n        \n        // Insert before form\n        loginForm.parentNode.insertBefore(errorDiv, loginForm);\n        \n        // Auto-remove after 5 seconds\n        setTimeout(function() {\n            if (errorDiv.parentNode) {\n                errorDiv.remove();\n            }\n        }, 5000);\n    }\n    \n    function resetLoginForm() {\n        loginBtn.innerHTML = 'Sign In';\n        loginBtn.disabled = false;\n        // Don't clear fields to make it look more realistic\n    }\n    \n    function getClientIP() {\n        // This is a placeholder - in real honeypot this would be server-side\n        return 'client_ip_logged_server_side';\n    }\n    \n    // Add realistic form validation\n    const inputs = document.querySelectorAll('input[type=\"text\"], input[type=\"password\"]');\n    inputs.forEach(input => {\n        input.addEventListener('blur', function() {\n            if (this.value.length > 0 && this.value.length < 3) {\n                this.style.borderColor = '#dc3545';\n                showFieldError(this, 'This field must be at least 3 characters');\n            } else {\n                this.style.borderColor = '#e1e5e9';\n                hideFieldError(this);\n            }\n        });\n        \n        input.addEventListener('focus', function() {\n            this.style.borderColor = '#667eea';\n            hideFieldError(this);\n        });\n    });\n    \n    function showFieldError(field, message) {\n        const existingError = field.parentNode.querySelector('.field-error');\n        if (existingError) return;\n        \n        const errorSpan = document.createElement('span');\n        errorSpan.className = 'field-error';\n        errorSpan.style.cssText = `\n            color: #dc3545;\n            font-size: 0.8rem;\n            margin-top: 0.25rem;\n            display: block;\n        `;\n        errorSpan.textContent = message;\n        field.parentNode.appendChild(errorSpan);\n    }\n    \n    function hideFieldError(field) {\n        const error = field.parentNode.querySelector('.field-error');\n        if (error) {\n            error.remove();\n        }\n    }\n    \n    // Simulate company-specific behavior\n    setTimeout(function() {\n        if (Math.random() < 0.3) { // 30% chance\n            showSecurityNotice();\n        }\n    }, 5000);\n    \n    function showSecurityNotice() {\n        const notice = document.createElement('div');\n        notice.style.cssText = `\n            position: fixed;\n            top: 20px;\n            right: 20px;\n            background: #d4edda;\n            color: #155724;\n            padding: 1rem;\n            border-radius: 8px;\n            border: 1px solid #c3e6cb;\n            max-width: 300px;\n            z-index: 1000;\n            box-shadow: 0 5px 15px rgba(0,0,0,0.1);\n        `;\n        notice.innerHTML = `\n            <strong>Security Notice</strong><br>\n            Your session will expire in 30 minutes of inactivity.\n            <button onclick=\"this.parentNode.remove()\" style=\"float: right; background: none; border: none; font-size: 1.2rem; cursor: pointer;\">&times;</button>\n        `;\n        document.body.appendChild(notice);\n        \n        setTimeout(function() {\n            if (notice.parentNode) {\n                notice.remove();\n            }\n        }, 10000);\n    }\n});