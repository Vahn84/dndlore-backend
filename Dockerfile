# Backend Dockerfile
FROM node:18-alpine

# Create app directory
WORKDIR /app

# Ensure TLS root certificates are available for outbound HTTPS/TLS (MongoDB Atlas)
RUN apk add --no-cache ca-certificates && update-ca-certificates

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --production

# Copy app source
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Expose port (dynamic; defaults to 10101 in production)
EXPOSE 10101

# Start the application
CMD ["node", "index.js"]
