FROM node:18-alpine

# Create app directory
WORKDIR /app

# Copy dependency files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy app source
COPY . .

# App runs on port 3000
EXPOSE 3000

# Start the app
CMD ["npm", "start"]