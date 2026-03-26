# 2026_Spring_Cryptography_Engineering

## Critique (100 points)

Please read the paper: **Password Managers: Attacks and Defenses David Silver, Suman Jana, and Dan Boneh, Stanford University; Eric Chen and Collin Jackson, Carnegie Mellon University.** then write a critique about this paper.

The critique should follow the following request:

- English text-only, about 1000-1200 words
- Realization of a technical specification, mechanism or algorithm to mitigate this paper.
- Please be free to use ChatGPT, Gemini, or other AI tools to assist your studies and let me know which answer seems more reasonable
- Please answer the following questions in your critique
  - Name of the paper:
  - Summary:
    - What problem is the paper trying to solve?
    - Why does the problem matter?
    - What is the approach used to solve the problem?
    - What is the conclusion drawn from this work?
    - Strength(s) of the paper:
    - Weakness(es) of the paper:
  - Your own reflection, which can include but not limited to:
    - What did you learn from this paper?
    - How would you improve or extend the work if you were the author?
    - What are the unsolved questions that you want to investigate?
    - What are the broader impacts of this proposed technology?
    - Else?
  - Realization of a technical specification or algorithm to mitigate this paper.

## Implementation (100 points)

### Implementation Notes

- You may directly use the provided Dockerfile in the template to set up the environment. **Except for libraries that are explicitly restricted**, you are free to install and use additional packages as needed.
- We will run your program using the following commands. If your program requires additional commands to run properly, please **clearly document them in the README**.

  ```bash
  cd project1
  docker compose up --build -d
  docker compose exec app uvicorn phase1.app.main:app \
          --host 0.0.0.0 --port 8000 --reload
  docker compose exec app uvicorn phase2.app.main:app \
          --host 0.0.0.0 --port 8000 --reload
  docker compose exec app uvicorn phase3.app.main:app \
          --host 0.0.0.0 --port 8000 --reload
  ```

- If the execution process is unclear, or if we are unable to successfully run your program by following your instructions, the score will be **0**.
- If execution fails
  1. Email us within **one week after the grades are released** and submit an updated README to clarify the execution steps so that we can verify the process.
  2. The score will be **reduced to 60% of the original score**. Note that the resubmission **only applies to the README and does not include any modifications to the source code**.
- Demo Video: To ensure that the program runs correctly on each student's own environment, record a demo video demonstrating the functionality of all three phases. More details will be described in the following sections.

### Phase 1 -- Understanding Credential Theft: The "Evil" Login Page (Offensive Basics) password (20 points)

- Goal: Build a fake login page that "steals" a username and password.
- Tasks:
  - **(10 points)** UI Design: Create a simple HTML page that looks like the **actual portal login**.
  - **(5 points)** The Trap: When the user clicks "Login," send the data to a Python script that saves the password to a `.txt` file.
  - **(5 points)** Redirection: After stealing the data, redirect the user to the **real website** so they do not suspect anything.
- Notes:
  - The UI of the login interface should resemble the real website that the page eventually redirects to as closely as possible (e.g., the E3 login interface, etc.).
  - After the redirect, the password entered by the user can simply be stored in plain text in a `.txt` file.

### Phase 2 -- Implementing a 6-Digit SMS/App Code: Building Your Own "Authenticator" (Symmetric 2FA) two factor (40 points)

- Goal: Make a login system that requires both a password and a 6-digit code.
- Tasks:
  1. **(5 points)** Make a login system which enables register and login.
  2. **(10 points)** Secret Sharing: Generate a random string (Secret Key) and show it to the user.
  3. **(15 points)** Use the current time and the Secret Key to calculate a 6-digit code using HMAC-SHA1.
  4. **(10 points)** Validation: The user enters the code from their app; the server checks if it matches. Allow for a "30-second window" (if the user is slightly slow, the code still works).
     - **Key Concept:** How does the server know the code without the user sending the Secret Key over the internet?
- Notes:
  1. You may use third-party authenticator applications such as **Google Authenticator**; implementing the authenticator app itself is **not required**.
  2. However, you **may not use libraries that directly implement TOTP**, such as **PyOTP**. The cryptographic logic for generating the TOTP code must be **implemented manually**.

### Phase 3 -- Simplified Hardware Login (WebAuthn): The "Digital Pass Key" (Asymmetric 2FA) (40 points)

- Goal: Use a digital signature instead of a password or one-time code to authenticate a user.
- Tasks:
  1. Registration: The website should pop up an interface that allows the user to save the private key; the user can choose to save it on the computer (if supported) or on another supported device.
  2. The Challenge: When logging in, the server sends a random **challenge string** to the browser.
  3. The Signature: The challenge is signed by the authenticator (e.g. your device), and sent back to the server.
  4. Verification: The server uses the **Public Key** to verify the signature.
- Grading:
  1. **(15 points)** The user can successfully register, and the application fulfills the specifications described above.
  2. **(15 points)** The user can successfully log in, and the application fulfills the specifications described above.
  3. **(10 points)** The application should reject the request and display the reason when encountering the following scenarios:
     - The user tries to register with a username that is already registered.
     - The user tries to log in with a username that is not registered.
     - The "save private key" process is canceled during registration.
     - The validation process is canceled during login.
- Note:
  - The `navigator.credentials` API is highly recommended, as it allows the browser to handle the "saving private key" process for you.
  - The `webauthn` library in Python is also highly recommended, so you do not need to generate and verify the challenge yourself.
  - Example website: `https://webauthn.io/`

### Demo Video

- The video must not exceed **3 minutes**.
- Include a file named `video.txt` in the submission folder, containing the **YouTube or cloud storage link** to the video.

### Grading

- **Critique:** Contributes 10% to the final score and is graded out of 100 points.
- **Implementation:** Contributes 5% to the final score and is graded out of 100 points.
  - Phase 1: 20 points
  - Phase 2: 40 points
  - Phase 3: 40 points
  - Demo Video: 20 points will be deducted if not submitted.
- **Late Submission Penalty:** A penalty of 0.5 points (to the final score) per day will be applied for late submissions, up to a maximum of 20 days. Beyond 20 days, late submissions will be assigned zero.

### Submission Guidelines

Upload a zip file that contains:

```text
<group_number>_project1/
├─phase1/
├─phase2/
├─phase3/
├─README.md
├─.dockerignore
├─docker-compose.yml
├─Dockerfile
├─requirements.txt
├─(other environment related files)
├─<group_number>_critique.pdf
└─video.txt
```
