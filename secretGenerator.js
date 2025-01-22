const crypto = require('crypto');

// Function to generate a secure random secret of 128 characters
function generateSecret(length = 128) {
  // Generate random bytes and encode them in base64 (without padding)
  const secret = crypto.randomBytes(length).toString('base64').replace(/=/g, '');
  // Limit the length to the desired size (128 characters)
  return secret.substring(0, length);
}

// Generate and log the secret
const secret = generateSecret(128);
console.log("Generated Secret:", secret);