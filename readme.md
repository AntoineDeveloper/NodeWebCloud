# NodeWebCloud - Self-hosted File Server

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-AntoineDeveloper-blue)
![Version](https://img.shields.io/badge/version-1.0.0-blue)

## Overview

**NodeWebCloud** is a fast, self-hostable cloud storage solution similar to Google Drive and Nextcloud, but optimized for performance. Built with **Node.js**, **Express**, and **MongoDB**, it provides a reliable file management system with great features such as user authentication, file sharing, role-based access, static url sharing, and more.

NodeWebCloud allows you to easily upload, organize, and share files within a web interface, giving you the flexibility to control your own cloud storage server.

## Features

- **User Authentication**: Secure login system with JWT token-based session management.
- **File Management**: Upload, view, and organize files in a hierarchical folder structure.
- **Role-based Access Control**: Admin and regular user roles with customizable permissions.
- **Easy to use**: An easy to use Web UI

## How It Works

1. **User Authentication**: Users log in through the login page. Upon successful authentication, they receive a JWT token for session management.
2. **Dashboard**: Once logged in, users are redirected to their dashboard where they can manage their files and folders.
3. **File Management**: Files are organized in folders, allowing easy navigation. Users can upload, view, and manage files within the system.
4. **Admin Features**: Admin users can manage other users, view their permissions, and perform system-wide administrative tasks.
5. **Role-based Permissions**: Each user is assigned a role (e.g., admin, regular user), determining their level of access to various system features.

## Contributions

We are always open to contributions and highly encourage them! If you have an idea, bug fix, or new feature in mind, feel free to open a pull request (PR). We are more than happy to review it and merge it into the project.

### How to Contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature-name`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add a new feature'`).
5. Push to your branch (`git push origin feature/your-feature-name`).
6. Open a pull request to the `LATEST VERSION (example: v1.5.2)` branch of this repository.

### What We Look For:
- Code that is well-organized and well-documented.
- Tests (if applicable) to cover new features or bug fixes.
- Respect for the existing code style and project structure.

We will review your PR as soon as possible and will merge it if everything looks good. Thanks for contributing!

## Prerequisites

To run NodeWebCloud locally, ensure you have the following dependencies installed:

- **Computer/Server/VM/LXC** With enough storage to fit your needs
- **Node.js** (>=14.0.0)
- **MongoDB** (either local or remote instance)
- **npm** for package management

## Installation Guide

Follow these steps to get NodeWebCloud up and running:

1. Clone the repository:
   ```bash
   git clone https://github.com/AntoineDeveloper/NodeWebCloud
   cd NodeWebCloud
   ```

2. NPM dependencies
    - They are already included in this repo
    - You do not need to do anything, but if you wish you can remove the packages and reinstall them!

3. Configure your environment:
    > Make a folder called "files" in the root of the project
    ```bash
   mkdir files
   ```

    > Copy the example .env to your production .env

   ```bash
   cp ./Setup/example.env .env
   ```

   > Open in nano text editor (Linux)
   ```bash
   nano .env
   ```
   > For Windows, simply use Notepad

   You need to configure several configuration parameters inside the .env
   ```dosini
   # This is the port where the web server is hosted
   WEB_PORT=3083

   # This is the secret for JWT User Sessions
   # You can use: node secretGenerator.js
   USERS_SECRET=A_STRONG_SECRET

   # This is the url to connect to your MongoDB Database (If you have authentication include it)
   MONGOOSE_CONNECT_STRING=mongodb://nodewebcloud:password@ip:27017/NODEWEBCLOUD?authSource=admin
   ```

   To save and exit (nano)
    - CTRL + O
    - Y
    - CTRL + X

4. Initial Database configuration
    > Run the following to create a new ADMIN account
    ```bash
    node createNewAdminAccount.js
    ```
   > Follow the on screen instructions

5. **Ready to launch!!**
    ```bash
    node server.js
    ```

    > You can now access the Web UI at the IP Address of the machine it's running on and the port you specified. *Example: 192.168.10.5:3083*
