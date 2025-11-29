# Maxelo Business Solutions - Work Management System

A comprehensive work management system built with Flask and PostgreSQL.

## Features

- **Admin Dashboard**: Manage employees, send notifications, view login logs
- **Employee Dashboard**: Messaging, file management, to-do lists
- **Role-based Access**: Admin, Employee, or Both roles
- **File Management**: Upload, download, and organize files
- **Real-time Messaging**: Send messages with file attachments
- **To-Do Lists**: Priority-based task management

## Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL
- pip

### Installation

1. **Clone or download the project**
2. **Setup Virtual Environment**:
   ```bash
   # Run the setup script
   python setup.py
   
   # Or manually:
   python -m venv venv
   venv\Scripts\activate  # Windows
   source venv/bin/activate  # macOS/Linux
   pip install -r requirements.txt