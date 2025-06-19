# static/js/app.js */
// CSRF Token Management
function getCSRFToken() {
    return document.querySelector('meta[name=csrf-token]').getAttribute('content');
}

// Notification System
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    // Add notification styles if not already present
    if (!document.querySelector('#notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                background: white;
                color: #2d3748;
                padding: 1rem 1.5rem;
                border-radius: 8px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.15);
                z-index: 1000;
                display: flex;
                align-items: center;
                gap: 1rem;
                max-width: 400px;
                animation: slideIn 0.3s ease;
                border-left: 4px solid #4299e1;
            }
            
            .notification-success {
                border-left-color: #48bb78;
                background: #c6f6d5;
                color: #22543d;
            }
            
            .notification-error {
                border-left-color: #f56565;
                background: #fed7d7;
                color: #742a2a;
            }
            
            .notification-warning {
                border-left-color: #ed8936;
                background: #feebc8;
                color: #7b341e;
            }
            
            .notification-close {
                background: none;
                border: none;
                font-size: 1.2rem;
                cursor: pointer;
                color: inherit;
                opacity: 0.7;
                padding: 0;
                width: 1.5rem;
                height: 1.5rem;
            }
            
            .notification-close:hover {
                opacity: 1;
            }
            
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            
            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (notification.parentElement) {
                notification.parentElement.removeChild(notification);
            }
        }, 300);
    }, 5000);
}

// Modal Management
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId = null) {
    if (modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'none';
        }
    } else {
        // Close all modals
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    }
    document.body.style.overflow = 'auto';
}

// Close modal when clicking outside
document.addEventListener('click', function(event) {
    if (event.target.classList.contains('modal')) {
        closeModal();
    }
});

// Form Validation Enhancement
document.addEventListener('DOMContentLoaded', function() {
    // Add real-time validation to forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input[required], select[required]');
        inputs.forEach(input => {
            input.addEventListener('blur', validateField);
            input.addEventListener('input', clearFieldError);
        });
    });
    
    // Auto-dismiss flash messages
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            alert.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (alert.parentElement) {
                    alert.remove();
                }
            }, 300);
        });
    }, 5000);
});

function validateField(event) {
    const field = event.target;
    const value = field.value.trim();
    
    // Remove existing error
    clearFieldError(event);
    
    if (field.hasAttribute('required') && !value) {
        showFieldError(field, 'This field is required');
        return false;
    }
    
    if (field.type === 'email' && value && !isValidEmail(value)) {
        showFieldError(field, 'Please enter a valid email address');
        return false;
    }
    
    if (field.type === 'number' && value) {
        const num = parseFloat(value);
        const min = field.getAttribute('min');
        const max = field.getAttribute('max');
        
        if (min && num < parseFloat(min)) {
            showFieldError(field, `Value must be at least ${min}`);
            return false;
        }
        
        if (max && num > parseFloat(max)) {
            showFieldError(field, `Value must not exceed ${max}`);
            return false;
        }
    }
    
    return true;
}

function clearFieldError(event) {
    const field = event.target;
    const errorDiv = field.parentElement.querySelector('.field-error');
    if (errorDiv) {
        errorDiv.remove();
    }
    field.classList.remove('error');
}

function showFieldError(field, message) {
    field.classList.add('error');
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error';
    errorDiv.textContent = message;
    errorDiv.style.cssText = `
        color: #f56565;
        font-size: 0.9rem;
        margin-top: 0.25rem;
    `;
    
    field.parentElement.appendChild(errorDiv);
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Loading States
function setLoading(element, loading = true) {
    if (loading) {
        element.disabled = true;
        element.dataset.originalText = element.textContent;
        element.textContent = 'Loading...';
        element.classList.add('loading');
    } else {
        element.disabled = false;
        element.textContent = element.dataset.originalText || element.textContent.replace('Loading...', '');
        element.classList.remove('loading');
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(event) {
    // Escape key closes modals
    if (event.key === 'Escape') {
        closeModal();
    }
    
    // Ctrl+/ or Cmd+/ for help (future feature)
    if ((event.ctrlKey || event.metaKey) && event.key === '/') {
        event.preventDefault();
        // Show help modal (implement when needed)
    }
});

// Add error class for form validation styling
const additionalStyles = `
    .form-input.error, .form-select.error {
        border-color: #f56565;
        box-shadow: 0 0 0 3px rgba(245, 101, 101, 0.1);
    }
    
    .loading {
        opacity: 0.7;
        cursor: not-allowed;
    }
`;

if (!document.querySelector('#additional-styles')) {
    const style = document.createElement('style');
    style.id = 'additional-styles';
    style.textContent = additionalStyles;
    document.head.appendChild(style);
}