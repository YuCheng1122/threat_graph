# **API Web Development Project**


## **Overview**


This project is a web API application that includes configurations, controllers, models, routes, schemas, utility scripts, and tests. The application is built using Python and follows a modular structure to ensure scalability and maintainability.

## **Setup**


1. **Install LAMP server:**
    
    ```bash
    sudo apt update && sudo apt upgrade -y && sudo apt autoremove
    sudo apt install tasksel
    sudo tasksel # Select "web server"
    sudo apt install php libapache2-mod-php
    sudo systemctl restart apache2
    ```
    
2. **Install MySQL:**
    
    ```bash
    sudo apt install mysql-server
    ```
    
3. **Install phpMyAdmin:**
    
    ```bash
    sudo apt install phpmyadmin
    ```
    
4. **Build Database:**

    
5. **Clone the repository:**
    
    ```bash
    git clone https://github.com/YuCheng1122/threat_graph.git
    cd threat_graph
    ```
    
6. **Create and activate a virtual environment:**
    
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
    
7. **Install the dependencies:**
    
    ```bash
    pip install -r requirements.txt
    ```
    
8. **Run the application:**
    
    ```bash
    python run.py
    ```

## **Running Tests**


To run the tests, use:

```bash
pytest
