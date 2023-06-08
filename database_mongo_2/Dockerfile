# Use the official MongoDB image as the base
FROM mongo:latest

# Set environment variables if needed (replace <VARIABLE> with the actual value)
ENV MONGO_INITDB_ROOT_USERNAME=pnuser
ENV MONGO_INITDB_ROOT_PASSWORD=supersecurepassword

# Copy any custom scripts or configuration files (if any)
# COPY custom_script.sh /docker-entrypoint-initdb.d/

# Expose the default MongoDB port
EXPOSE 27017
