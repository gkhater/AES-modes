AES Modes Demo — How to Run



This repository contains a demonstration of AES encryption modes, implemented with:



a Python Flask backend (server.py) that performs encryption/decryption



a React + Vite frontend that provides an interactive UI



The project is intended for coursework demonstration purposes.



1\. Prerequisites



Before running the project, ensure the following are installed:



1.1 Python (3.9 or newer)



Download: https://www.python.org/downloads/



Verify installation:



python --version



1.2 Node.js (includes npm)



Download: https://nodejs.org/



Verify installation:



node --version

npm --version



1.3 Git



Download: https://git-scm.com/



Verify installation:



git --version





2\. Clone the Repository



Open Command Prompt (CMD) and run:



git clone https://github.com/gkhater/AES-modes.git

cd AES-modes





You should now see the following structure:



AES-modes/

│

├── frontend/

└── server/



3\. Run the Backend (Flask Server)

3.1 Navigate to the backend folder

cd server



3.2 Create a virtual environment

python -m venv .venv



3.3 Activate the virtual environment (CMD)

.\\.venv\\Scripts\\activate





The command prompt should now show:



(.venv) ...



3.4 Install Python dependencies

pip install -r requirements.txt



3.5 Start the Flask server

python server.py





Expected output:



&nbsp;\* Serving Flask app 'server'

&nbsp;\* Running on http://127.0.0.1:5000





✅ Leave this CMD window open — the backend must remain running.



4\. Run the Frontend (React + Vite)



Open a new CMD window.



4.1 Navigate to the frontend folder

cd AES-modes\\frontend



4.2 Install frontend dependencies

npm install



4.3 Start the development server

npm run dev





Expected output:



Local: http://localhost:5173/





Open this URL in a web browser.



No additional configuration is required.



6\. Using the Demo



Open the frontend in the browser (localhost:5173)



Enter a plaintext message and AES key



Select an encryption mode (ECB, CBC, CFB, etc.)



Click Encrypt



Use Decrypt to recover the original plaintext



All cryptographic operations are performed by the Flask backend



7\. Notes



This project uses a development Flask server and is not intended for production deployment.



Both backend and frontend must be running simultaneously.



The demo video was recorded following the steps above.



AI was used only to help with the UI.



8\. Stopping the Application



Backend: press CTRL + C in the backend CMD window



Frontend: press CTRL + C in the frontend CMD window

