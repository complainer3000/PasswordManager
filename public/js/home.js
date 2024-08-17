const userToken = localStorage.getItem('userToken');

document.querySelectorAll('.copy-password').forEach(button => {
    button.addEventListener('click', function() {
        const actualPassword = this.closest('li').dataset.password;
        navigator.clipboard.writeText(actualPassword)
            .then(() => alert('Password copied to clipboard'))
            .catch(err => console.error('Failed to copy: ', err));
    });
});

function generatePassword(inputElement) {
    fetch('/generate-password')
        .then(response => response.json())
        .then(data => {
            inputElement.value = data.password;
        })
        .catch(error => console.error('Error:', error));
}

document.getElementById('generatePassword').addEventListener('click', function() {
    generatePassword(document.querySelector('input[name="password"]'));
});

const modal = document.getElementById('editModal');
const closeBtn = document.getElementsByClassName('close')[0];
const editForm = document.getElementById('editCredentialForm');

document.querySelectorAll('.edit-credential').forEach(button => {
    button.addEventListener('click', function() {
        const li = this.closest('li');
        const id = li.dataset.id;
        const site = li.querySelector('.credential-value.site').textContent.trim();
        const username = li.querySelector('.credential-value.username').textContent.trim();
        const password = li.dataset.password;

        document.getElementById('editId').value = id;
        document.getElementById('editSite').value = site;
        document.getElementById('editUsername').value = username;
        document.getElementById('editPassword').value = password;

        modal.style.display = 'block';
    });
});

document.querySelectorAll('.delete-credential').forEach(button => {
    button.addEventListener('click', function() {
        const li = this.closest('li');
        const id = li.dataset.id;
        removeCredential(id);
    });
});

document.getElementById('generateEditPassword').addEventListener('click', function() {
    generatePassword(document.getElementById('editPassword'));
});

closeBtn.onclick = function() {
    modal.style.display = 'none';
}

window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}

editForm.onsubmit = function(e) {
    e.preventDefault();
    const formData = new FormData(editForm);
    formData.append('token', userToken);
    fetch('/edit-credential', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(Object.fromEntries(formData))
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            alert('Failed to update credential: ' + (data.message || 'Unknown error'));
        }
    })
    .catch(error => console.error('Error:', error));
}

function togglePasswordVisibility(icon) {
    const input = icon.previousElementSibling;
    if (input.type === 'password') {
        input.type = 'text';
        icon.textContent = '🙈';
    } else {
        input.type = 'password';
        icon.textContent = '👁️';
    }
}

function removeCredential(id) {
    if (confirm('Are you sure you want to delete this credential?')) {
        fetch('/remove-credential', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ id: id, token: userToken })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Failed to remove credential: ' + (data.message || 'Unknown error'));
            }
        })
        .catch(error => console.error('Error:', error));
    }
}

document.querySelector('form[action="/add-credentials"]').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    const data = Object.fromEntries(formData);
    data.token = userToken; // Make sure userToken is defined and correct

    fetch('/add-credentials', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw err; });
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            throw new Error(data.message || 'Unknown error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to add credential: ' + (error.message || 'Unknown error'));
    });
});

fetch('/add-credentials', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify(data)
    })
    .then(response => {
    if (!response.ok) {
        return response.text().then(text => {
        throw new Error(`HTTP error! status: ${response.status}, message: ${text}`);
        });
    }
    const contentType = response.headers.get("content-type");
    if (!contentType || !contentType.includes("application/json")) {
        throw new Error("Oops, we haven't got JSON!");
    }
    return response.json();
    })
    .then(data => {
    if (data.success) {
        location.reload();
    } else {
        throw new Error(data.message || 'Unknown error');
    }
    })
    .catch(error => {
    console.error('Error:', error);
    alert('Failed to add credential: ' + error.message);
});