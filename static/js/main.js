/**
 * NetworkPentestPro - Main JavaScript
 * Handles client-side functionality for the GUI application
 */

// Initialize theme handling
document.addEventListener('DOMContentLoaded', function() {
    // Check for stored theme preference
    const storedTheme = localStorage.getItem('theme') || 'dark';
    applyTheme(storedTheme);
    
    // Add theme toggle button event listener if it exists
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    // Initialize tooltips if Bootstrap is present
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // Add responsive handling for tables
    const tables = document.querySelectorAll('.table-responsive');
    tables.forEach(makeTableResponsive);
    
    // Add collapsible sections handling
    const collapsibles = document.querySelectorAll('.collapsible-header');
    collapsibles.forEach(setupCollapsible);
});

/**
 * Apply specified theme to document
 * @param {string} theme - The theme to apply ('dark' or 'light')
 */
function applyTheme(theme) {
    document.body.classList.remove('dark', 'light');
    document.body.classList.add(theme);
    localStorage.setItem('theme', theme);
    
    // Update theme-specific elements
    const themeIcons = document.querySelectorAll('.theme-icon');
    themeIcons.forEach(icon => {
        if (theme === 'dark') {
            icon.textContent = '🌙';
        } else {
            icon.textContent = '☀️';
        }
    });
}

/**
 * Toggle between dark and light themes
 */
function toggleTheme() {
    const currentTheme = localStorage.getItem('theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(newTheme);
}

/**
 * Set up a collapsible section
 * @param {Element} header - The collapsible section header
 */
function setupCollapsible(header) {
    const content = header.nextElementSibling;
    if (!content) return;
    
    content.style.display = 'none';
    header.classList.add('collapsed');
    
    header.addEventListener('click', function() {
        if (content.style.display === 'none') {
            content.style.display = 'block';
            header.classList.remove('collapsed');
            header.classList.add('expanded');
        } else {
            content.style.display = 'none';
            header.classList.remove('expanded');
            header.classList.add('collapsed');
        }
    });
}

/**
 * Make a table responsive
 * @param {Element} tableContainer - The table container element
 */
function makeTableResponsive(tableContainer) {
    const table = tableContainer.querySelector('table');
    if (!table) return;
    
    if (table.offsetWidth > tableContainer.offsetWidth) {
        tableContainer.classList.add('table-overflow');
    }
}

/**
 * Update progress bar value
 * @param {string} id - The progress bar element ID
 * @param {number} value - The progress value (0-100)
 * @param {string} [label] - Optional text to display
 */
function updateProgress(id, value, label) {
    const progressBar = document.getElementById(id);
    if (!progressBar) return;
    
    const bar = progressBar.querySelector('.progress-bar');
    if (!bar) return;
    
    bar.style.width = `${value}%`;
    bar.setAttribute('aria-valuenow', value);
    
    if (label) {
        bar.textContent = label;
    } else {
        bar.textContent = `${Math.round(value)}%`;
    }
}

/**
 * Display a network risk score visualization
 * @param {string} id - The risk score element ID
 * @param {number} score - The risk score (0-100)
 */
function displayRiskScore(id, score) {
    const riskElement = document.getElementById(id);
    if (!riskElement) return;
    
    const riskBar = riskElement.querySelector('.risk-bar');
    const riskIndicator = riskElement.querySelector('.risk-indicator');
    const riskLabel = riskElement.querySelector('.risk-label');
    
    if (riskBar) {
        riskBar.style.width = '100%';
    }
    
    if (riskIndicator) {
        riskIndicator.style.left = `${score}%`;
    }
    
    if (riskLabel) {
        let riskText = 'Low';
        let riskClass = 'text-success';
        
        if (score > 80) {
            riskText = 'Critical';
            riskClass = 'text-danger';
        } else if (score > 60) {
            riskText = 'High';
            riskClass = 'text-warning';
        } else if (score > 40) {
            riskText = 'Medium';
            riskClass = 'text-warning';
        } else if (score > 20) {
            riskText = 'Low';
            riskClass = 'text-success';
        } else {
            riskText = 'Very Low';
            riskClass = 'text-success';
        }
        
        riskLabel.textContent = `${score}/100 (${riskText})`;
        riskLabel.className = riskClass;
    }
}

/**
 * Add a message to the console output
 * @param {string} message - The message text
 * @param {string} [type] - Message type (error, warning, success, info)
 */
function addConsoleMessage(message, type) {
    const console = document.getElementById('console-output');
    if (!console) return;
    
    const timestamp = new Date().toTimeString().split(' ')[0];
    const msgElement = document.createElement('div');
    
    if (type) {
        msgElement.classList.add(`console-${type}`);
    }
    
    msgElement.textContent = `[${timestamp}] ${message}`;
    console.appendChild(msgElement);
    
    // Auto-scroll to bottom
    console.scrollTop = console.scrollHeight;
}

/**
 * Create a signal strength visualization
 * @param {number} strength - Signal strength percentage (0-100)
 * @returns {HTMLElement} Signal visualization element
 */
function createSignalVisualization(strength) {
    const container = document.createElement('div');
    container.className = 'signal-meter';
    
    let strengthClass = 'signal-strength-low';
    if (strength > 70) {
        strengthClass = 'signal-strength-high';
    } else if (strength > 40) {
        strengthClass = 'signal-strength-medium';
    }
    
    container.classList.add(strengthClass);
    
    for (let i = 1; i <= 4; i++) {
        const bar = document.createElement('div');
        bar.className = `signal-bar signal-bar-${i}`;
        
        // Only show active bars based on strength
        if ((i === 1 && strength > 0) || 
            (i === 2 && strength > 25) || 
            (i === 3 && strength > 50) || 
            (i === 4 && strength > 75)) {
            bar.classList.add('active');
        }
        
        container.appendChild(bar);
    }
    
    return container;
}

/**
 * Format network security type with appropriate visual cues
 * @param {string} security - Security type string
 * @returns {HTMLElement} Formatted security display element
 */
function formatSecurityType(security) {
    const container = document.createElement('div');
    container.className = 'security-type';
    
    const indicator = document.createElement('span');
    indicator.className = 'status-indicator';
    
    let statusClass = 'status-secure';
    
    if (security === 'Open' || security === 'None') {
        statusClass = 'status-insecure';
    } else if (security === 'WEP') {
        statusClass = 'status-insecure';
    } else if (security.includes('WPA') && !security.includes('WPA2')) {
        statusClass = 'status-warning';
    }
    
    indicator.classList.add(statusClass);
    container.appendChild(indicator);
    
    const text = document.createElement('span');
    text.textContent = security;
    container.appendChild(text);
    
    return container;
}

/**
 * Validate user input for form fields
 * @param {string} formId - Form element ID
 * @returns {boolean} True if validation passes
 */
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    let isValid = true;
    const requiredFields = form.querySelectorAll('[required]');
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('is-invalid');
            isValid = false;
        } else {
            field.classList.remove('is-invalid');
        }
    });
    
    return isValid;
}
