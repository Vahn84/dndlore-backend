const fs = require('fs');
const path = require('path');

// Copia .env.example in .env se quest'ultimo non esiste
const examplePath = path.join(__dirname, '..', '.env.development');
const envPath = path.join(__dirname, '..', '.env');

if (!fs.existsSync(envPath) && fs.existsSync(examplePath)) {
  fs.copyFileSync(examplePath, envPath);
  console.log('Creato file .env a partire da .env.example');
} else {
  console.log('.env presente o .env.example mancante');
}