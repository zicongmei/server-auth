function showMessage(text, type) {
    const msg = document.getElementById('message');
    msg.textContent = text;
    msg.className = 'message ' + type;
    msg.style.display = 'block';
    setTimeout(() => msg.style.display = 'none', 3000);
}

async function loadUsers() {
    const response = await fetch('/api/admin/users');
    const users = await response.json();
    const tbody = document.getElementById('users-list');
    tbody.innerHTML = users.map(user =>
        '<tr>' +
            '<td>' + user + '</td>' +
            '<td>' +
                '<button class="btn btn-secondary" onclick="prepareChangePassword(\'' + user + '\')">Change Password</button> ' +
                (user !== 'root' ?
                    '<button class="btn btn-danger" onclick="deleteUser(\'' + user + '\')">Delete</button>' :
                    '<em>Cannot delete root</em>'
                ) +
            '</td>' +
        '</tr>'
    ).join('');
}

function prepareChangePassword(username) {
    document.getElementById('new-username').value = username;
    document.getElementById('new-password').focus();
}

async function deleteUser(username) {
    if (!confirm('Delete user ' + username + '?')) return;

    const response = await fetch('/api/admin/users', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });

    if (response.ok) {
        showMessage('User deleted successfully', 'success');
        loadUsers();
    } else {
        const error = await response.text();
        showMessage(error, 'error');
    }
}

document.getElementById('createUserForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('new-username').value;
    const password = document.getElementById('new-password').value;

    const response = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        showMessage('User saved successfully', 'success');
        document.getElementById('createUserForm').reset();
        loadUsers();
    } else {
        const error = await response.text();
        showMessage(error, 'error');
    }
});

async function logout() {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
}

loadUsers();
