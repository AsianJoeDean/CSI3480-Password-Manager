// The encryption key only exists while the vault is unlocked
let currentKey = null;

// Run this function when the page loads
window.onload = function() {
    if (localStorage.getItem('masterSalt') && localStorage.getItem('masterVerifier')) {
        document.getElementById('unlockSection').style.display = 'block';
    } else {
        document.getElementById('createMasterSection').style.display = 'block';
    }
};

// Master Password Stuff

async function createMasterPassword() {
    const password = document.getElementById('createMasterPassword').value;
    const confirmPassword = document.getElementById('confirmMasterPassword').value;

    if (password.length < 8) {
        alert('Master password must be at least 8 characters.');
        return;
    }

    if (password !== confirmPassword) {
        alert('Master passwords do not match.');
        return;
    }

    // Create a random salt
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    currentKey = await getVaultKey(password, salt);

    // Store an encrypted test value so we can check the master password later
    const verifier = await encryptPassword('correct-master-password');

    localStorage.setItem('masterSalt', bytesToBase64(salt));
    localStorage.setItem('masterVerifier', verifier);

    document.getElementById('createMasterPassword').value = '';
    document.getElementById('confirmMasterPassword').value = '';
    openVault();
}

async function unlockVault() {
    const password = document.getElementById('masterPassword').value;
    const savedSalt = localStorage.getItem('masterSalt');
    const savedVerifier = localStorage.getItem('masterVerifier');

    if (!password || !savedSalt || !savedVerifier) {
        alert('Unable to unlock vault.');
        return;
    }

    try {
        const salt = base64ToBytes(savedSalt);
        currentKey = await getVaultKey(password, salt);

        const verifier = await decryptPassword(savedVerifier);

        if (verifier !== 'correct-master-password') {
            throw new Error('Incorrect password');
        }

        document.getElementById('masterPassword').value = '';
        openVault();
    } catch (e) {
        currentKey = null;
        alert('Incorrect master password.');
    }
}

function openVault() {
    document.getElementById('loginSection').style.display = 'none';
    document.getElementById('vaultSection').style.display = 'block';
    displayVault();
}

function lockVault() {
    currentKey = null;
    document.getElementById('vaultSection').style.display = 'none';
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('createMasterSection').style.display = 'none';
    document.getElementById('unlockSection').style.display = 'block';
    document.getElementById('vaultDisplay').innerHTML = '';
}

// --- ENCRYPTION UTILITIES ---

// This replaces the original static demo key
// PBKDF2 derives an AES key from the user's master password
async function getVaultKey(masterPassword, salt) {
    const rawKey = new TextEncoder().encode(masterPassword);

    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        'PBKDF2',
        false,
        ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 250000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptPassword(plainTextPassword) {
    if (!currentKey) {
        throw new Error('Vault is locked.');
    }

    const encodedText = new TextEncoder().encode(plainTextPassword);

    // Create a random initialization vector (IV) for added security
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        currentKey,
        encodedText
    );

    // Combine the IV and encrypted data so we can decrypt it later
    const encryptedBytes = new Uint8Array(encryptedContent);
    const combined = new Uint8Array(iv.length + encryptedBytes.length);
    combined.set(iv);
    combined.set(encryptedBytes, iv.length);

    // Convert to base64 for storage in localStorage
    return bytesToBase64(combined);
}

async function decryptPassword(encryptedBase64) {
    if (!currentKey) {
        throw new Error('Vault is locked.');
    }

    // Convert the base64 string back to raw bytes
    const combined = base64ToBytes(encryptedBase64);

    // Extract the IV (first 12 bytes) and encrypted data
    const iv = combined.slice(0, 12);
    const encryptedBytes = combined.slice(12);

    const decryptedContent = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        currentKey,
        encryptedBytes
    );

    return new TextDecoder().decode(decryptedContent);
}

function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(base64) {
    return new Uint8Array(atob(base64).split('').map(char => char.charCodeAt(0)));
}

// --- VAULT LOGIC ---

async function saveToVault() {
    // 1. Get the values from the HTML inputs
    // Get the values from the HTML inputs
    const websiteInput = document.getElementById('website').value;
    const usernameInput = document.getElementById('username').value;
    const passwordInput = document.getElementById('password').value;

    if (!websiteInput || !usernameInput || !passwordInput) {
        alert('Please fill in all fields!');
        return;
    }

    // 2. Pull the existing vault from localStorage (or create an empty array if it doesn't exist)
    // Pull the existing vault from localStorage (or create an empty array)
    let vault = JSON.parse(localStorage.getItem('myPasswordVaultSecure')) || [];

    // 3. ENCRYPT THE PASSWORD HERE before saving
    // Encrypt each credential before saving it
    const securedWebsite = await encryptPassword(websiteInput);
    const securedUsername = await encryptPassword(usernameInput);
    const securedPassword = await encryptPassword(passwordInput);

    const newEntry = {
        website: securedWebsite,
        username: securedUsername,
        password: securedPassword
    };

    // 4. Save the updated vault back to localStorage as a string

    // Save the updated vault back to localStorage as a string
    vault.push(newEntry);
    localStorage.setItem('myPasswordVaultSecure', JSON.stringify(vault));

    // 5. Clear the input fields and refresh the display
    // Clear the inputs and refresh the display
    document.getElementById('website').value = '';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    displayVault();
}

async function displayVault() {
    const vaultDisplay = document.getElementById('vaultDisplay');
    let vault = JSON.parse(localStorage.getItem('myPasswordVaultSecure')) || [];

    vaultDisplay.innerHTML = '';

    if (vault.length === 0) {
        vaultDisplay.innerHTML = '<p>No saved passwords yet.</p>';
        return;
    }

    // A normal for loop makes it easy to connect each entry to its delete button
    for (let i = 0; i < vault.length; i++) {
        try {
            const decryptedWebsite = await decryptPassword(vault[i].website);
            const decryptedUsername = await decryptPassword(vault[i].username);
            const decryptedPassword = await decryptPassword(vault[i].password);

            const item = document.createElement('p');
            item.innerHTML = `<strong>${decryptedWebsite}</strong><br>${decryptedUsername}<br>`;

            const passwordText = document.createElement('span');
            passwordText.textContent = decryptedPassword;
            item.appendChild(passwordText);
            item.appendChild(document.createElement('br'));

            const copyButton = document.createElement('button');
            copyButton.textContent = 'Copy';
            copyButton.onclick = function() {
                navigator.clipboard.writeText(decryptedPassword);
            };

            const deleteButton = document.createElement('button');
            deleteButton.textContent = 'Delete';
            deleteButton.onclick = function() {
                deleteEntry(i);
            };

            item.appendChild(copyButton);
            item.appendChild(deleteButton);
            vaultDisplay.appendChild(item);
        } catch (e) {
            const item = document.createElement('p');
            item.textContent = '[Decryption Failed]';
            vaultDisplay.appendChild(item);
        }
    }
}
function resetVault() {
    const confirmed = confirm(
        'Reset the vault? This will delete all saved passwords and the master password.'
    );

    if (!confirmed) {
        return;
    }

    localStorage.removeItem('myPasswordVaultSecure');
    localStorage.removeItem('masterSalt');
    localStorage.removeItem('masterVerifier');

    currentKey = null;

    document.getElementById('vaultSection').style.display = 'none';
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('unlockSection').style.display = 'none';
    document.getElementById('createMasterSection').style.display = 'block';
    document.getElementById('vaultDisplay').innerHTML = '';

    alert('Vault has been reset.');
}

function deleteEntry(index) {
    let vault = JSON.parse(localStorage.getItem('myPasswordVaultSecure')) || [];
    vault.splice(index, 1);
    localStorage.setItem('myPasswordVaultSecure', JSON.stringify(vault));
    displayVault();
}

// --- GENERATOR LOGIC ---

function generateSecurePassword(length = 16) {
    // All the possible characters we want in our passwords
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:,.<>?';

    // Create an array to hold cryptographically secure random numbers
    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);

    let generatedPassword = "";

    // Loop through our random numbers and pick a corresponding character from our list
    for (let i = 0; i < length; i++) {
        generatedPassword += chars[randomValues[i] % chars.length];
    }

    return generatedPassword;
}

function fillGeneratedPassword() {
    const length = Number(document.getElementById('passwordLength').value) || 16;
    const newPassword = generateSecurePassword(length);
    document.getElementById('password').value = newPassword;
}
