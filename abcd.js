// Run this in Node.js
const crypto = require('crypto');

// --- Configuration ---
// PASTE THE BASE64 STRING FROM THE *CORRECTED* PYTHON SCRIPT HERE:
const b64Message = "R/VNqLZTpsq0aPwQSN9gKkp1SWNduEoe61cAgsVbaTiTKV22oXvDNjpmaLgoYYmlfShU"; // Example string

const PASSWORD = "MySecure"; // The same 8-letter string

// --- Component lengths (in bytes) ---
// These MUST match the Python script
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16; // AES-GCM tag is 128 bits (16 bytes)

/**
 * Decrypts a Base64 string (salt + iv + tag + ciphertext)
 * using a password.
 */
function decryptPin(b64Data, password) {
  console.log("Attempting to decrypt...");

  try {
    // 1. Decode and unpack the message
    // 
    const messageBuffer = Buffer.from(b64Data, 'base64');

    // Extract each part from the buffer based on its known length
    const salt = messageBuffer.subarray(0, SALT_LEN);
    const iv = messageBuffer.subarray(SALT_LEN, SALT_LEN + IV_LEN);
    const authTag = messageBuffer.subarray(
      SALT_LEN + IV_LEN,
      SALT_LEN + IV_LEN + TAG_LEN
    );
    const ciphertext = messageBuffer.subarray(SALT_LEN + IV_LEN + TAG_LEN);

    console.log(` > Salt: ${salt.toString('hex')}`);
    console.log(` > IV: ${iv.toString('hex')}`);
    console.log(` > Auth Tag: ${authTag.toString('hex')}`);
    console.log(` > Ciphertext: ${ciphertext.toString('hex')}`);

    // 2. Re-derive the *exact same* key
    // We use the same parameters as Python:
    // - PBKDF2
    // - 480000 iterations
    // - 32-byte (256-bit) key
    // - SHA256 hash
    console.log("Re-deriving key from password and salt...");
    const key = crypto.pbkdf2Sync(
      password,
      salt,
      480000, 
      32, 
      'sha256'
    );
    console.log(" > Key derived.");

    // 3. Decrypt with AES-256-GCM
    // Create the decipher object
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

    // Set the authentication tag. This is critical for GCM.
    // If this tag doesn't match, decryption will fail.
    decipher.setAuthTag(authTag);

    // Decrypt the ciphertext
    let decrypted = decipher.update(ciphertext, 'binary', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;

  } catch (err) {
    // This block catches errors, which typically happen if:
    // 1. The password is wrong (wrong key is derived)
    // 2. The data is tampered with (auth tag mismatch)
    // 3. The data is corrupt
    console.error("\n--- DECRYPTION FAILED! ---");
    console.error(err.message);
    return null;
  }
}

// --- Run Decryption ---
console.log("--- Node.js (Decrypt) ---");
const decryptedPin = decryptPin(b64Message, PASSWORD);

if (decryptedPin) {
  console.log(`\n✅ Success! Decrypted PIN: ${decryptedPin}`);
} else {
  console.log("\n❌ Failed to decrypt PIN. Check password or data string.");
}