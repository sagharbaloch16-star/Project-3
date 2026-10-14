# DecodeLabs — Phishing Awareness Analysis

A beginner-friendly Python desktop application that analyzes pasted emails and messages for common phishing warning signs.

## Features

- Detects urgency and pressure language.
- Flags wording about passwords, OTPs, and account verification.
- Identifies suspicious prize, threat, and payment-related wording.
- Extracts links and flags some URL patterns for careful review.
- Displays a suspicion score, verdict, red flags, explanation, and recommended actions.
- Includes sample messages for testing.
- Does not open links or connect to external services.

## Technologies

- Python 3
- Tkinter for the graphical user interface
- Python standard library (`re`, `urllib.parse`)

No third-party packages are required.

## Project Files

```text
Phishing_Awareness_Analysis/
├── main.py
├── analyzer.py
├── README.md
├── sample_messages.txt
├── requirements.txt
└── .gitignore
```

## Requirements

- Python 3.9 or newer recommended.
- Tkinter available in your Python installation.
- Visual Studio Code or another Python editor (optional).

## How to Run

1. Download and extract the project ZIP.
2. Open the `Phishing_Awareness_Analysis` folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Run:

   ```powershell
   python main.py
   ```

   If that does not work on Windows, try:

   ```powershell
   py main.py
   ```

5. Paste an email or message into the text area.
6. Click **Analyze Message** to see the results.
7. Click **Load Sample** to test a fictional example, or **Clear** to reset the form.

## How It Works

The application uses simple keyword and URL-pattern rules to look for common warning signs. It then produces a heuristic score and recommendations for safer behavior.

## Example Test Message

```text
Subject: Urgent account verification

Your account will be suspended within 2 hours. Verify your password and OTP immediately at:
http://example-login.invalid/verify
```

Expected warning signs include urgency, password/OTP wording, and an HTTP link.

## Important Security Notes

- The score is a basic heuristic, not a probability that a message is malicious.
- A low-suspicion result does **not** prove a message is safe.
- The app does not check live domain reputation, scan attachments, or contact external services.
- Links are displayed as text and are never opened by the application.
- Do not paste real passwords, OTPs, or confidential information into test messages.

## Future Improvements

- Add unit tests and more sample messages.
- Improve URL analysis and reduce false positives.
- Add report export functionality.
- Integrate a trusted threat-intelligence service with appropriate safeguards.

## Author

**DecodeLabs — Cyber Security Project 3**

*Educational project for phishing awareness and basic message analysis.*
