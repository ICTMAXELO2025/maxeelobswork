// Dashboard specific JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts if needed
    initializeCharts();
    
    // Real-time updates for notifications
    if (typeof(EventSource) !== "undefined") {
        // You can implement Server-Sent Events for real-time updates
    }
    
    // Auto-complete for employee search
    initializeSearch();
});

function initializeCharts() {
    // Placeholder for chart initialization
    // You can integrate Chart.js or other libraries here
}

function initializeSearch() {
    // Initialize search functionality based on page
    const adminSearch = document.getElementById('adminEmployeeSearch');
    const employeeSearch = document.getElementById('employeeSearch');
    
    if (adminSearch) {
        searchEmployees('adminEmployeeSearch', 'adminSearchResults', true);
    }
    
    if (employeeSearch) {
        searchEmployees('employeeSearch', 'employeeSearchResults', false);
    }
}

// To-Do list functionality
function toggleTodo(todoId) {
    fetch(`/admin/todo/update/${todoId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'complete=true'
    }).then(response => {
        window.location.reload();
    });
}

function deleteTodo(todoId) {
    if (confirm('Are you sure you want to delete this task?')) {
        fetch(`/admin/todo/update/${todoId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'delete=true'
        }).then(response => {
            window.location.reload();
        });
    }
}

// File management
function createFolder() {
    const folderName = prompt('Enter folder name:');
    if (folderName && folderName.trim()) {
        // This would be handled by your form submission
        document.getElementById('folder_name').value = folderName;
        document.getElementById('createFolderForm').submit();
    }
}

// Message functionality
function markAsRead(messageId) {
    fetch(`/admin/mark-message-read/${messageId}`)
        .then(response => {
            document.getElementById(`message-${messageId}`).style.opacity = '0.7';
        });
}

// Responsive menu toggle for mobile
function toggleMenu() {
    const nav = document.querySelector('.dashboard-nav');
    nav.classList.toggle('mobile-active');
}