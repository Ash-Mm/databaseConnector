# Use an official Node.js runtime as the base image
FROM node:20-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
# to install dependencies
COPY package.json package-lock.json ./

# Install application dependencies
# The --omit=dev flag ensures devDependencies are not installed in production
RUN npm install --omit=dev

# Copy the rest of your application code to the container
COPY . .

# Ensure the uploads directory exists
# This is important if your app relies on it for dynamic content
RUN mkdir -p uploads

# Expose the port your app runs on
# This should match the PORT environment variable or the default port your server listens on (e.g., 5000)
EXPOSE 5000

# Command to run your application
# This tells Docker how to start your server.js
CMD ["node", "server.js"]
