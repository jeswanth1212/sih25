
# QuMail Complete Setup Guide
## ISRO Smart India Hackathon 2025 - Manual Configuration Steps

### 🚀 WHAT YOU NEED TO DO MANUALLY:

#### 1. Gmail App Password Setup (REQUIRED for Task 36)
```
Step 1: Enable 2-Factor Authentication on Gmail
   - Go to https://myaccount.google.com/security
   - Enable 2-Step Verification if not already enabled

Step 2: Generate App Password for QuMail
   - Go to https://myaccount.google.com/apppasswords
   - Select "Mail" as the app type
   - Generate password (16 characters, no spaces)
   - SAVE this password - you'll need it for QuMail

Step 3: Configure QuMail Frontend
   - Open QuMail application
   - Click "Gmail Setup" button (top-left corner)
   - Enter your Gmail address
   - Enter the 16-character App Password (NOT your regular password)
   - Click "Save & Connect"
```

#### 2. Test Email Accounts (RECOMMENDED for Demo)
```
Option A: Use Your Own Gmail
   - Use your personal Gmail with App Password
   - Send test emails to yourself

Option B: Create Test Gmail Accounts
   - Create: qumail.alice.test@gmail.com
   - Create: qumail.bob.test@gmail.com  
   - Set up App Passwords for both
   - Use for send/receive testing
```

#### 3. Backend Server (AUTO-STARTED)
```
✅ Backend is already running on http://localhost:5000
✅ All APIs are functional
✅ Email integration is ready
```

#### 4. Frontend Application (AUTO-STARTED)
```
✅ Frontend is running on http://localhost:3000
✅ Email integration module loaded
✅ Real encryption API connected
✅ QKD simulation active
```

### 🧪 TESTING STEPS:

#### Test 1: Basic Connection
```
1. Open QuMail frontend
2. Check browser console for:
   - "✅ Connected to QuMail Backend Encryption API"
   - "✅ Connected to QuMail Email Integration API"
   - "📧 QuMail Email Integration Initialized"
```

#### Test 2: Gmail Configuration
```
1. Click "Gmail Setup" button
2. Enter valid Gmail + App Password
3. Should see: "✅ Gmail credentials configured successfully!"
```

#### Test 3: Send Encrypted Email
```
1. Fill out email form:
   - To: recipient@gmail.com
   - Subject: QuMail Test
   - Message: Hello from QuMail!
   - Security Level: 2 (Quantum-aided AES)
2. Click "Send Secure"
3. Should see encryption + sending process
4. Check recipient's Gmail for encrypted email
```

#### Test 4: Receive Encrypted Email
```
1. Use browser console: emailIntegration.receiveEmails(5)
2. Should fetch and decrypt emails
3. QuMail emails should show decrypted content
```

### 🎯 DEMO READINESS CHECKLIST:

- [ ] Gmail App Password configured
- [ ] Test email accounts set up
- [ ] Backend server running (✅ Already done)
- [ ] Frontend application running (✅ Already done)
- [ ] Email sending tested
- [ ] Email receiving tested
- [ ] All 4 security levels working
- [ ] QKD key generation active

### 🏆 SUCCESS INDICATORS:

When everything is working, you should see:
- ✅ Emails send successfully via Gmail SMTP
- ✅ Emails encrypted with chosen security level
- ✅ QuMail headers in sent emails
- ✅ Encrypted JSON attachments
- ✅ Email receiving and decryption working
- ✅ Signature verification for Levels 2-3

### 🚨 TROUBLESHOOTING:

Problem: "Authentication failed"
Solution: Use App Password, not regular Gmail password

Problem: "Email integration not available"
Solution: Check backend server is running on port 5000

Problem: "Frontend not connecting"
Solution: Check frontend is running on port 3000

Problem: "QKD keys not generating"
Solution: Check QKD simulation is active in backend

### 📞 SUPPORT:
All APIs are implemented and tested. Only manual configuration needed!
