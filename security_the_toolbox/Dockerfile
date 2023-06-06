# Use the official Node.js image as the base image
FROM node:14

# Create a working directory for the application
WORKDIR /usr/src/app

# Copy package.json and package-lock.json into the working directory
COPY package*.json ./

# Install application dependencies
RUN npm i
RUN npm i -g pm2

# Copy the application source code into the working directory
COPY ./app.js .

# Expose the port the application will run on
EXPOSE 5000

# Start the application
CMD ["pm2-runtime", "app.js"]
