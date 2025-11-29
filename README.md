[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/DxqGQVx4)

extra info on use of app (if needed):

Link to UI prototype:

Link to Kanban:
https://miro.com/app/board/uXjVJz9YZbw=/

Link to audio/video of feedback:

Other:

How to run the app locally
- Create and activate a virtual environment:
  - Windows:
      python -m venv venv
      venv\Scripts\activate
  - macOS / Linux:
      python3 -m venv venv
      source venv/bin/activate
- Install dependencies (example):
      pip install Flask werkzeug supabase-py openpyxl pillow requests psycopg2-binary
  or if you have a requirements file:
      pip install -r requirements.txt
- Start the app:
      python run.py
- Open the app in your browser:
  - Local URL: http://127.0.0.1:5000/
  - This will redirect to the login page.

Notes:
- If you plan to embed images in Excel exports, install 'requests', 'openpyxl' and 'Pillow' as above.
- Ensure environment variables are set (e.g., SMTP, Supabase keys) or configure them in a .env file (and add to .gitignore).
