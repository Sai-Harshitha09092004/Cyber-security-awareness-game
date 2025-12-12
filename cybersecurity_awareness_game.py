#!/usr/bin/env python3
# File: cybersecurity_awareness_game.py
"""
cybersecurity_awareness_game.py

Cybersecurity Awareness Game (enhanced):
- Dynamic quiz: selects 10 random questions from a larger bank every play.
- Improved frontend (tkinter + ttk): progress bar, question card, feedback flow.
- Modules: Quiz, Phishing Spotter, Password Strength, Summary, High Scores.
- Stores high scores in high_scores.json in the same directory.

Run:
    python cybersecurity_awareness_game.py

Requirements:
    - Python 3.8+ (no external packages required)
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import random
import json
import os
import re
import time
from datetime import datetime
from collections import namedtuple

# ---------------------------
# Config & Data
# ---------------------------
DATA_DIR = os.path.dirname(__file__)
SCORES_FILE = os.path.join(DATA_DIR, "high_scores.json")

QuizItem = namedtuple("QuizItem", ["q", "choices", "answer", "explain", "points"])

# Larger question bank (20+ items). Quiz will pick 10 random questions each session.
QUIZ_BANK = [
    QuizItem("What does the CIA triad stand for?",
             ["Confidentiality, Integrity, Availability",
              "Control, Identify, Authenticate",
              "Confidentiality, Identity, Authorization",
              "Control, Integrity, Availability"],
             0, "CIA = Confidentiality, Integrity, Availability.", 10),

    QuizItem("Which is the best practice for storing user passwords?",
             ["Plaintext in DB", "Hashed with salt (bcrypt/argon2)",
              "Encrypted with reversible key in DB", "Store in code"],
             1, "Use slow KDFs (bcrypt/argon2) with unique salts.", 10),

    QuizItem("What is XSS primarily used for?",
             ["Encrypt server traffic", "Run scripts in victim browsers",
              "Break TLS certificates", "Scan internal networks"],
             1, "XSS injects scripts that run in other users' browsers.", 10),

    QuizItem("What is a safe way to protect an API?",
             ["Use plain HTTP", "Use HTTPS + authentication + rate limiting",
              "Allow all origins", "Store keys in client code"],
             1, "Use HTTPS, proper auth, and throttling to protect APIs.", 10),

    QuizItem("What does MFA stand for and why use it?",
             ["Multi-Factor Authentication: adds extra verification layers",
              "Mandatory File Access", "Multiple Firewall Access", "Mainframe Auth"],
             0, "MFA reduces risk from compromised passwords.", 10),

    QuizItem("What is SQL Injection?",
             ["A database optimization", "An input-based attack injecting SQL",
              "A hashing algorithm", "A type of encryption"],
             1, "SQL Injection executes malicious SQL via untrusted inputs.", 10),

    QuizItem("What is CSRF?",
             ["Cross-Site Request Forgery: unauthorized actions via user's browser",
              "Cross-Site Resource Fetch", "Certificate Revocation Service", "Cloud Service Request"],
             0, "CSRF tricks the browser into making unintended authenticated requests.", 10),

    QuizItem("What header mitigates Clickjacking?",
             ["Content-Security-Policy", "X-Frame-Options", "Server", "Cache-Control"],
             1, "X-Frame-Options or CSP frame-ancestors prevent clickjacking.", 10),

    QuizItem("Which is safer for long-term secret storage in AWS?",
             ["Store in code", "Use AWS Secrets Manager", "Plain S3 object", "Hardcoded env var"],
             1, "Use Secrets Manager or Parameter Store with KMS for sensitive secrets.", 10),

    QuizItem("How should cookies storing session tokens be protected?",
             ["HttpOnly + Secure + SameSite", "LocalStorage", "In URL query", "Disable TLS"],
             0, "HttpOnly, Secure, and SameSite help protect cookies from theft and CSRF.", 10),

    QuizItem("What does 'least privilege' mean?",
             ["Give full admin to everyone", "Grant minimal permissions necessary",
              "No permissions to anyone", "Rotate passwords weekly"],
             1, "Least privilege grants only the permissions required to perform a task.", 10),

    QuizItem("Why use HTTPS/TLS?",
             ["Faster responses", "Encrypts data in transit and prevents MITM",
              "Obfuscates code", "Reduces server load"],
             1, "TLS provides confidentiality, integrity, and authentication for connections.", 10),

    QuizItem("What is a phishing email red flag?",
             ["Personalized sender name", "Suspicious domain and urgent call-to-action",
              "Known sender", "Email from coworker domain"],
             1, "Look for suspicious domains, odd links, and urgent requests for credentials.", 10),

    QuizItem("What is a typical defense against brute force?",
             ["No login limits", "Rate limiting + account lockouts + MFA",
              "Store plaintext passwords", "Use default passwords"],
             1, "Rate limiting, lockouts, and MFA help stop brute-force attacks.", 10),

    QuizItem("When should you verify a TLS certificate in code?",
             ["Never", "Always", "Only in production", "Only on mobile"],
             1, "Always validate certificates to prevent MITM attacks.", 10),

    QuizItem("What is an IDOR vulnerability?",
             ["Improper Direct Object Reference allowing unauthorized data access",
              "Internet Distributed Object Repository", "Inactive Domain Of Record", "Invalid Data Order"],
             0, "IDOR lets attackers access objects by manipulating identifiers without auth checks.", 10),

    QuizItem("What does 'input validation' prevent?",
             ["Only typos", "Many injection attacks and malformed input issues",
              "Network latency", "Disk corruption"],
             1, "Proper validation reduces risk of SQLi, XSS, and other injections.", 10),

    QuizItem("Which tool is commonly used for web app security testing?",
             ["Burp Suite", "Excel", "Postman only", "Notepad"],
             0, "Burp Suite is widely used for intercepting and testing web security.", 10),

    QuizItem("Why rotate secrets (API keys, certificates)?",
             ["To increase complexity", "To reduce risk if compromised",
              "To slow the server", "To break integrations"],
             1, "Rotation limits window of exposure if a secret leaks.", 10),

    QuizItem("What is privilege escalation?",
             ["Gaining higher permissions than intended", "Logging out", "Encrypting a file", "Restarting a service"],
             0, "Attackers exploit flaws to gain higher privileges on a system.", 10),
]

PHISHING_SCENARIOS = [
    {
        "title": "Invoice from Unknown Vendor",
        "email": [
            "From: invoices@payworld.com",
            "To: you@example.com",
            "Subject: URGENT - Outstanding payment",
            "",
            "Hi,",
            "Please pay the attached invoice to avoid late fees.",
            "Click this link to view the invoice: http://payworld-invoices.example.attacker.com/view?id=123",
            "Thank you,",
            "Accounts Receivable"
        ],
        "suspicious_indices": [6],
        "explain": "The clickable link uses a suspicious/typo domain. Always verify sender domains and attachments."
    },
    {
        "title": "Password Reset Request",
        "email": [
            "From: support@bank-fast.example.com",
            "To: you@example.com",
            "Subject: Reset your password immediately",
            "",
            "We noticed suspicious activity. Reset your banking password here: https://secure-bank.example.com/reset?user=you",
            "If you didn't request this, reply with your full name and account number.",
            "Sincerely, Support Team"
        ],
        "suspicious_indices": [5, 6],
        "explain": "Legitimate banks will not ask for account numbers by reply. Check the link and sender carefully."
    }
]

# ---------------------------
# Utilities (high scores, password strength)
# ---------------------------
def load_high_scores():
    if not os.path.exists(SCORES_FILE):
        return []
    try:
        with open(SCORES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_high_scores(scores):
    try:
        with open(SCORES_FILE, "w", encoding="utf-8") as f:
            json.dump(scores, f, indent=2)
    except Exception as e:
        print("Error saving scores:", e)

def add_high_score(name, score):
    scores = load_high_scores()
    scores.append({"name": name, "score": score, "time": datetime.utcnow().isoformat()})
    scores = sorted(scores, key=lambda s: s["score"], reverse=True)[:10]
    save_high_scores(scores)

def password_strength(password):
    length = len(password)
    classes = 0
    classes += bool(re.search(r"[0-9]", password))
    classes += bool(re.search(r"[a-z]", password))
    classes += bool(re.search(r"[A-Z]", password))
    classes += bool(re.search(r"[^\w\s]", password))
    score = 0
    if length >= 8:
        score += 2
    elif length >= 6:
        score += 1
    score += classes
    return min(5, score)  # 0..5

# ---------------------------
# GUI Application
# ---------------------------
class GameApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cybersecurity Awareness Game")
        self.geometry("980x640")
        self.configure(bg="#f4f7fb")
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("Card.TFrame", background="white", relief="flat")
        self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), background="#f4f7fb")
        self.style.configure("Lead.TLabel", font=("Segoe UI", 12), background="#f4f7fb")
        self.style.configure("Question.TLabel", font=("Segoe UI", 14), background="white")
        self.style.configure("Answer.TRadiobutton", font=("Segoe UI", 12))
        self.style.configure("Primary.TButton", font=("Segoe UI", 11, "bold"))
        self.user_name = None
        self.total_score = 0
        self.start_time = time.time()
        self.quiz_questions = []
        self.quiz_total = 10
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)
        self.frames = {}
        for F in (HomeFrame, EnhancedQuizFrame, PasswordFrame, PhishingFrame, SummaryFrame, HighScoresFrame):
            frame = F(container, self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame("HomeFrame")

    def show_frame(self, name):
        frame = self.frames[name]
        frame.tkraise()

    def register_name(self):
        if not self.user_name:
            name = simpledialog.askstring("Your name", "Enter your name for the score board:", parent=self)
            if name:
                self.user_name = name

    def finish_and_show_summary(self):
        self.register_name()
        if self.user_name:
            add_high_score(self.user_name, self.total_score)
        self.show_frame("SummaryFrame")
        self.frames["SummaryFrame"].update_summary()

# ---------------------------
# Frames
# ---------------------------
class HomeFrame(ttk.Frame):
    def __init__(self, parent, controller: GameApp):
        super().__init__(parent, padding=14)
        self.controller = controller
        ttk.Label(self, text="Cybersecurity Awareness Game", style="Title.TLabel").pack(pady=(8,4))
        ttk.Label(self, text="Interactive learning — improved quiz UI with 10 random questions each time.", style="Lead.TLabel").pack(pady=(0,12))
        card = ttk.Frame(self, style="Card.TFrame", padding=16)
        card.pack(fill="x", padx=18, pady=8)
        ttk.Label(card, text="Modules", font=("Segoe UI", 13, "bold"), background="white").pack(anchor="w")
        btns = ttk.Frame(card, padding=(0,8))
        btns.pack(anchor="w")
        ttk.Button(btns, text="Play Quiz (10 random Qs)", style="Primary.TButton",
                   command=self.start_quiz, width=28).grid(row=0, column=0, padx=6, pady=8)
        ttk.Button(btns, text="Phishing Spotter", command=lambda: controller.show_frame("PhishingFrame"), width=20).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Password Strength", command=lambda: controller.show_frame("PasswordFrame"), width=20).grid(row=0, column=2, padx=6)
        ttk.Button(self, text="High Scores", command=lambda: controller.show_frame("HighScoresFrame")).pack(pady=(14,0))
        ttk.Button(self, text="Finish & Summary", command=controller.finish_and_show_summary).pack(pady=(10,0))

    def start_quiz(self):
        bank = QUIZ_BANK.copy()
        random.shuffle(bank)
        self.controller.quiz_questions = bank[:self.controller.quiz_total]
        qframe: EnhancedQuizFrame = self.controller.frames["EnhancedQuizFrame"]
        qframe.start_quiz(self.controller.quiz_questions)
        self.controller.show_frame("EnhancedQuizFrame")

class EnhancedQuizFrame(ttk.Frame):
    def __init__(self, parent, controller: GameApp):
        super().__init__(parent, padding=12)
        self.controller = controller
        self.current_index = 0
        self.score = 0
        self.answered = False
        header_frame = ttk.Frame(self)
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="Quiz — Test your security knowledge", style="Title.TLabel").pack(side="left", anchor="w")
        self.progress_label = ttk.Label(header_frame, text="", style="Lead.TLabel")
        self.progress_label.pack(side="right", anchor="e")
        self.card = ttk.Frame(self, style="Card.TFrame", padding=18)
        self.card.pack(fill="both", expand=True, padx=14, pady=12)
        self.question_var = tk.StringVar()
        self.question_label = ttk.Label(self.card, textvariable=self.question_var, style="Question.TLabel", wraplength=820, justify="left")
        self.question_label.pack(anchor="w", pady=(0,12))
        self.answer_var = tk.IntVar(value=-1)
        self.radio_buttons = []
        self.answers_frame = ttk.Frame(self.card)
        self.answers_frame.pack(anchor="w", pady=(0,12))
        for i in range(4):
            rb = ttk.Radiobutton(self.answers_frame, text="", variable=self.answer_var, value=i, style="Answer.TRadiobutton")
            rb.pack(anchor="w", pady=6, fill="x")
            self.radio_buttons.append(rb)
        self.explain_text = tk.Text(self.card, height=5, wrap="word", state="disabled", bg="white", relief="flat")
        self.explain_text.pack(fill="x", pady=(6,8))
        controls = ttk.Frame(self)
        controls.pack(fill="x", padx=14)
        self.progress = ttk.Progressbar(controls, length=420, maximum=controller.quiz_total, mode="determinate")
        self.progress.pack(side="left", padx=(0,12))
        btns = ttk.Frame(controls)
        btns.pack(side="right")
        self.submit_btn = ttk.Button(btns, text="Submit", command=self.submit_answer, style="Primary.TButton")
        self.submit_btn.grid(row=0, column=0, padx=6)
        self.next_btn = ttk.Button(btns, text="Next", command=self.next_question, state="disabled")
        self.next_btn.grid(row=0, column=1, padx=6)
        self.back_btn = ttk.Button(btns, text="Back Home", command=self.back_home)
        self.back_btn.grid(row=0, column=2, padx=6)
        self.score_var = tk.StringVar(value="Score: 0")
        ttk.Label(self, textvariable=self.score_var, font=("Segoe UI", 11, "bold")).pack(pady=(8,0))
        self.bind_all("<Key>", self.keypress_handler)

    def start_quiz(self, questions):
        self.questions = questions
        self.current_index = 0
        self.score = 0
        self.answered = False
        self.progress['value'] = 0
        self.score_var.set("Score: 0")
        self.load_question()

    def keypress_handler(self, event):
        if event.char in ("1","2","3","4"):
            val = int(event.char) - 1
            if 0 <= val < 4:
                self.answer_var.set(val)

    def load_question(self):
        if self.current_index >= len(self.questions):
            messagebox.showinfo("Quiz complete", f"You finished the quiz. Score: {self.score}")
            self.controller.total_score += self.score
            self.controller.show_frame("HomeFrame")
            return
        qi = self.questions[self.current_index]
        self.question_var.set(f"Q{self.current_index+1}. {qi.q}")
        for i, ch in enumerate(qi.choices):
            self.radio_buttons[i].config(text=f"{i+1}. {ch}", state="normal")
        self.answer_var.set(-1)
        self.answered = False
        self.next_btn.config(state="disabled")
        self.submit_btn.config(state="normal")
        self.explain_text.config(state="normal")
        self.explain_text.delete("1.0", "end")
        self.explain_text.config(state="disabled")
        self.progress_label.config(text=f"{self.current_index+1}/{len(self.questions)}")
        self.progress['value'] = self.current_index

    def submit_answer(self):
        sel = self.answer_var.get()
        if sel < 0:
            messagebox.showwarning("Select answer", "Choose an answer before submitting.")
            return
        if self.answered:
            return
        qi = self.questions[self.current_index]
        correct = (sel == qi.answer)
        if correct:
            self.score += qi.points
            self.show_feedback(True, qi.explain)
        else:
            self.show_feedback(False, qi.explain + f" Correct answer: {qi.choices[qi.answer]}")
        for rb in self.radio_buttons:
            rb.config(state="disabled")
        self.score_var.set(f"Score: {self.score}")
        self.answered = True
        self.submit_btn.config(state="disabled")
        self.next_btn.config(state="normal")

    def show_feedback(self, correct: bool, explanation: str):
        self.explain_text.config(state="normal")
        self.explain_text.delete("1.0", "end")
        if correct:
            self.explain_text.insert("end", "✔ Correct!\n\n", ("good",))
            self.explain_text.tag_config("good", foreground="green", font=("Segoe UI", 11, "bold"))
        else:
            self.explain_text.insert("end", "✖ Incorrect\n\n", ("bad",))
            self.explain_text.tag_config("bad", foreground="red", font=("Segoe UI", 11, "bold"))
        self.explain_text.insert("end", explanation + "\n")
        self.explain_text.config(state="disabled")

    def next_question(self):
        if not self.answered:
            return
        self.current_index += 1
        self.load_question()

    def back_home(self):
        if self.current_index < len(self.questions) - 1:
            if not messagebox.askyesno("Leave quiz?", "Quit quiz? Your score so far will be recorded."):
                return
        self.controller.total_score += self.score
        self.controller.show_frame("HomeFrame")

class PasswordFrame(ttk.Frame):
    def __init__(self, parent, controller: GameApp):
        super().__init__(parent, padding=12)
        self.controller = controller
        ttk.Label(self, text="Password Strength", style="Title.TLabel").pack(pady=(6,4))
        card = ttk.Frame(self, style="Card.TFrame", padding=12)
        card.pack(fill="x", padx=16)
        frm = ttk.Frame(card)
        frm.pack(pady=6, anchor="w")
        ttk.Label(frm, text="Enter password:", font=("Segoe UI", 11)).grid(row=0, column=0, padx=6)
        self.pw_entry = ttk.Entry(frm, show="*", width=36)
        self.pw_entry.grid(row=0, column=1, padx=6)
        ttk.Button(frm, text="Check", command=self.check_pw).grid(row=0, column=2, padx=6)
        self.result_var = tk.StringVar()
        ttk.Label(card, textvariable=self.result_var, font=("Segoe UI", 12, "bold"), background="white").pack(pady=(8,6))
        self.tips_text = tk.Text(card, height=6, wrap="word", state="disabled", bg="white", relief="flat")
        self.tips_text.pack(fill="x")

    def check_pw(self):
        pw = self.pw_entry.get()
        if not pw:
            messagebox.showwarning("Empty", "Type a password to evaluate.")
            return
        score = password_strength(pw)
        strengths = ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"]
        self.result_var.set(f"Strength: {strengths[score]} (score {score}/5)")
        tips = []
        if len(pw) < 8:
            tips.append("- Use at least 8 characters (longer is better).")
        if not re.search(r"[A-Z]", pw):
            tips.append("- Add uppercase letters.")
        if not re.search(r"[a-z]", pw):
            tips.append("- Add lowercase letters.")
        if not re.search(r"[0-9]", pw):
            tips.append("- Add digits.")
        if not re.search(r"[^\w\s]", pw):
            tips.append("- Add symbols (e.g., !@#$%).")
        if len(pw) >= 12 and score >= 4:
            tips.append("- Great! Consider a passphrase or password manager.")
        pts = max(0, (score - 1) * 5)
        if pts > 0:
            messagebox.showinfo("Points", f"You earned {pts} points for password strength!")
            self.controller.total_score += pts
        self.tips_text.config(state="normal")
        self.tips_text.delete("1.0", "end")
        self.tips_text.insert("end", "\n".join(tips) if tips else "No tips — looks good!")
        self.tips_text.config(state="disabled")

class PhishingFrame(ttk.Frame):
    def __init__(self, parent, controller: GameApp):
        super().__init__(parent, padding=12)
        self.controller = controller
        ttk.Label(self, text="Phishing Spotter", style="Title.TLabel").pack(pady=8)
        self.scenario_index = 0
        self.email_text = tk.Text(self, width=100, height=14, wrap="word")
        self.email_text.pack(pady=6)
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=6)
        ttk.Button(btn_frame, text="Load Example", command=self.load_example).grid(row=0, column=0, padx=6)
        ttk.Button(btn_frame, text="Mark Suspicious Lines", command=self.mark_lines).grid(row=0, column=1, padx=6)
        ttk.Button(btn_frame, text="Next Scenario", command=self.next_scenario).grid(row=0, column=2, padx=6)
        ttk.Button(btn_frame, text="Back Home", command=lambda: controller.show_frame("HomeFrame")).grid(row=0, column=3, padx=6)
        self.load_example()

    def load_example(self):
        sc = PHISHING_SCENARIOS[self.scenario_index]
        self.email_text.config(state="normal")
        self.email_text.delete("1.0", "end")
        for i, line in enumerate(sc["email"]):
            self.email_text.insert("end", f"{i:02d}: {line}\n")
        self.email_text.config(state="disabled")

    def next_scenario(self):
        self.scenario_index = (self.scenario_index + 1) % len(PHISHING_SCENARIOS)
        self.load_example()

    def mark_lines(self):
        s = simpledialog.askstring("Enter lines", "Enter comma-separated line numbers you find suspicious:", parent=self)
        if not s:
            return
        try:
            picks = [int(x.strip()) for x in s.split(",") if x.strip() != ""]
        except ValueError:
            messagebox.showerror("Invalid", "Enter numbers like: 3 or 3,6")
            return
        sc = PHISHING_SCENARIOS[self.scenario_index]
        correct = set(sc["suspicious_indices"])
        picks_set = set(picks)
        matched = picks_set & correct
        wrong = picks_set - correct
        missed = correct - picks_set
        points = max(0, 10 * len(matched) - 4 * len(wrong))
        msg = f"Matched: {sorted(list(matched))}\nWrong picks: {sorted(list(wrong))}\nMissed: {sorted(list(missed))}\n\n{sc['explain']}\n\nPoints gained: {points}"
        messagebox.showinfo("Result", msg)
        self.controller.total_score += points

class SummaryFrame(ttk.Frame):
    def __init__(self, parent, controller: GameApp):
        super().__init__(parent, padding=12)
        self.controller = controller
        ttk.Label(self, text="Session Summary", style="Title.TLabel").pack(pady=8)
        self.summary_label = ttk.Label(self, text="", justify="left", wraplength=820)
        self.summary_label.pack(pady=8)
        ttk.Button(self, text="Save Score & Back Home", command=self.save_and_home).pack(pady=6)
        ttk.Button(self, text="View High Scores", command=lambda: controller.show_frame("HighScoresFrame")).pack(pady=6)

    def update_summary(self):
        elapsed = int(time.time() - self.controller.start_time)
        txt = (f"Player: {self.controller.user_name or 'Anonymous'}\n"
               f"Total score earned this session: {self.controller.total_score}\n"
               f"Session length: {elapsed} seconds\n\n"
               "Recommendations:\n"
               " - Use multi-factor authentication where possible.\n"
               " - Use long passphrases and a password manager.\n"
               " - Be suspicious of unexpected emails & verify senders.\n"
               " - Follow least privilege and rotate secrets.\n")
        self.summary_label.config(text=txt)

    def save_and_home(self):
        self.controller.register_name()
        if self.controller.user_name:
            add_high_score(self.controller.user_name, self.controller.total_score)
        self.controller.total_score = 0
        self.controller.start_time = time.time()
        self.controller.show_frame("HomeFrame")

class HighScoresFrame(ttk.Frame):
    def __init__(self, parent, controller: GameApp):
        super().__init__(parent, padding=12)
        ttk.Label(self, text="High Scores", style="Title.TLabel").pack(pady=8)
        self.listbox = tk.Listbox(self, width=80, height=14)
        self.listbox.pack(pady=6)
        ttk.Button(self, text="Refresh", command=self.refresh).pack(pady=6)
        ttk.Button(self, text="Back Home", command=lambda: controller.show_frame("HomeFrame")).pack(pady=6)
        self.refresh()

    def refresh(self):
        self.listbox.delete(0, "end")
        scores = load_high_scores()
        if not scores:
            self.listbox.insert("end", "No high scores yet.")
            return
        for i, s in enumerate(scores, start=1):
            time_str = s.get("time", "")[:19].replace("T", " ")
            self.listbox.insert("end", f"{i}. {s['name']} - {s['score']} pts ({time_str} UTC)")

# ---------------------------
# Run application
# ---------------------------
def main():
    app = GameApp()
    messagebox.showinfo("Welcome", "Welcome! The quiz will pick 10 random questions each play. Good luck!")
    app.mainloop()

if __name__ == "__main__":
    main()
