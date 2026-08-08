// Run this function when the page loads to show existing passwords
window.onload = function() {
    displayVault();
};

// --- ENCRYPTION UTILITIES ---

// For this mini-project demo, we will use a static key. 
// In a production app, this would be derived from the user's Master Password.
async function getDemoKey() {
    const rawKey = new TextEncoder().encode("my-super-secret-master-key-12345"); 
    const hash = await window.crypto.subtle.digest('SHA-256', rawKey);
    return window.crypto.subtle.importKey("raw", hash, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptPassword(plainTextPassword) {
    const key = await getDemoKey();
    const encodedText = new TextEncoder().encode(plainTextPassword);
    
    // Create a random initialization vector (IV) for added security
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, encodedText);
    
    // Combine the IV and the encrypted data so we can decrypt it later
    const encryptedBytes = new Uint8Array(encryptedContent);
    const combined = new Uint8Array(iv.length + encryptedBytes.length);
    combined.set(iv);
    combined.set(encryptedBytes, iv.length);
    
    // Convert to a base64 string for easy storage in localStorage
    return btoa(String.fromCharCode.apply(null, combined));
}

async function decryptPassword(encryptedBase64) {
    try {
        const key = await getDemoKey();
        
        // Convert the base64 string back to raw bytes
        const combined = new Uint8Array(atob(encryptedBase64).split('').map(char => char.charCodeAt(0)));
        
        // Extract the IV (first 12 bytes) and the encrypted data
        const iv = combined.slice(0, 12);
        const encryptedBytes = combined.slice(12);
        
        const decryptedContent = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, encryptedBytes);
        return new TextDecoder().decode(decryptedContent);
    } catch (e) {
        return "[Decryption Failed]";
    }
}

// --- VAULT LOGIC ---

async function saveToVault() {
    // 1. Get the values from the HTML inputs
    const websiteInput = document.getElementById('website').value;
    const passwordInput = document.getElementById('password').value;

    if (!websiteInput || !passwordInput) {
        alert("Please fill in both fields!");
        return;
    }

    // 2. Pull the existing vault from localStorage (or create an empty array if it doesn't exist)
    let vault = JSON.parse(localStorage.getItem('myPasswordVault')) || [];

    // 3. ENCRYPT THE PASSWORD HERE before saving
    const securedPassword = await encryptPassword(passwordInput);

    const newEntry = {
        website: websiteInput,
        password: securedPassword // Saving the scrambled text, NOT the real password
    };
    
    // 4. Save the updated vault back to localStorage as a string
    vault.push(newEntry);
    localStorage.setItem('myPasswordVault', JSON.stringify(vault));

    // 5. Clear the input fields and refresh the display
    document.getElementById('website').value = '';
    document.getElementById('password').value = '';
    displayVault();
}

async function displayVault() {
    const vaultDisplay = document.getElementById('vaultDisplay');
    let vault = JSON.parse(localStorage.getItem('myPasswordVault')) || [];

    // Clear the current display
    vaultDisplay.innerHTML = '';

    // We use a for...of loop here because we are dealing with async decryption
    for (const entry of vault) {
        const decryptedPassword = await decryptPassword(entry.password);
        
        const item = document.createElement('p');
        // Now it displays the decrypted password to the user
        item.innerHTML = `<strong>${entry.website}:</strong> ${decryptedPassword}`;
        vaultDisplay.appendChild(item);
    }
}

// --- GENERATOR LOGIC ---

function generateSecurePassword(length = 16) {
    // All the possible characters we want in our passwords
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:,.<>?";
    
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
    // Generate a 16-character password
    const newPassword = generateSecurePassword(16);
    
    // Find the password input box on the screen and fill it in
    document.getElementById('password').value = newPassword;
}