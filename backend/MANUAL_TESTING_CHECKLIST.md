# QuMail Manual Testing Checklist
## ISRO Smart India Hackathon 2025 - Step-by-Step Verification Guide

### 🚀 HOW TO CHECK MANUALLY AFTER SETUP

---

## **PHASE 1: BASIC SYSTEM CHECK** ⚡

### ✅ Step 1: Verify Backend is Running
```bash
# Open browser and go to:
http://localhost:5000/

# You should see JSON response with:
{
  "service": "QuMail Hybrid Quantum-Classical Key Manager",
  "status": "operational",
  "components": {
    "qkd_available": true,
    "ecdh_available": true,
    "hybrid_available": true,
    "real_pqc_available": true
  }
}
```

### ✅ Step 2: Verify Frontend is Running
```bash
# Open browser and go to:
http://localhost:3000/

# You should see:
- QuMail interface with dark theme
- "Gmail Setup" button (top-left)
- Email compose form
- QKD panel button
- Security level selector
```

### ✅ Step 3: Check Browser Console
```bash
# Press F12 → Console tab
# Look for these messages:
✅ "QuMail Quantum Key Distribution System Initialized"
✅ "Connected to QuMail Backend Encryption API"  
✅ "Connected to QuMail Email Integration API"
✅ "QuMail Email Integration Initialized"

# If you see errors, backend might not be running
```

---

## **PHASE 2: EMAIL INTEGRATION CHECK** 📧

### ✅ Step 4: Test Gmail Setup Button
```bash
1. Click "Gmail Setup" button (top-left corner)
2. Modal should appear with:
   - Gmail Address field
   - App Password field
   - Setup instructions
   - "Save & Connect" button

# If button doesn't exist, email integration failed to load
```

### ✅ Step 5: Configure Gmail Credentials
```bash
1. Enter your Gmail address (e.g., your.email@gmail.com)
2. Enter your 16-character App Password (NOT regular password)
3. Click "Save & Connect"
4. Should see: "✅ Gmail credentials configured successfully!"

# If you see error, check App Password is correct
```

---

## **PHASE 3: ENCRYPTION SYSTEM CHECK** 🔐

### ✅ Step 6: Test QKD Key Generation
```bash
1. Click QKD panel button (if available)
2. Or press F12 → Console → Type:
   window.qkdManager.generateNewQuantumKey()
3. Should see new QKD key generated
4. Check key has: key_id, length (256 bits), protocol (BB84)

# If fails, QKD simulation has issues
```

### ✅ Step 7: Test Encryption Levels
```bash
# In browser console, type:
window.realEncryption.getSystemCapabilities()

# Should return:
{
  "real_encryption_available": true,
  "encryption_levels": [
    "Level 1: Quantum Secure (OTP)",
    "Level 2: Quantum-aided AES", 
    "Level 3: Hybrid PQC",
    "Level 4: No Quantum Security"
  ]
}
```

---

## **PHASE 4: EMAIL SENDING TEST** 📤

### ✅ Step 8: Fill Email Form
```bash
1. Fill out the email form:
   - To: recipient@gmail.com (use real email you can check)
   - Subject: QuMail Test - Level 2 Encryption
   - Message: Hello from QuMail! This is an encrypted test message.
   - Security Level: Select "Level 2" (Quantum-aided AES)
```

### ✅ Step 9: Send Test Email
```bash
1. Click "Send Secure" button
2. Watch browser console for:
   ✅ "Using real email sending via SMTP..."
   ✅ "Email sent successfully: [message_id]"
   ✅ "Algorithm: AES-256-GCM-Real-PQC"

# If you see "showing configuration modal", credentials not set
# If you see SMTP errors, check App Password
```

### ✅ Step 10: Verify Email Received
```bash
1. Check recipient's Gmail inbox
2. Look for email with subject: "QuMail Test - Level 2 Encryption"
3. Email should have:
   - X-QuMail-Version header
   - X-QuMail-Security-Level: 2
   - Encrypted JSON attachment: "qumail_encrypted_content.json"
   - Placeholder text for non-QuMail clients

# If no email received, check Gmail settings and App Password
```

---

## **PHASE 5: EMAIL RECEIVING TEST** 📬

### ✅ Step 11: Test Email Receiving
```bash
# In browser console, type:
emailIntegration.receiveEmails(5)

# Should see:
✅ "Received [X] emails"
✅ List of emails with metadata
✅ QuMail emails showing decrypted content

# If authentication error, check Gmail App Password
```

### ✅ Step 12: Test QuMail Email Detection
```bash
# In browser console, type:
emailIntegration.receiveQuMailEmails(5)

# Should see:
✅ "Received [X] QuMail encrypted emails"
✅ Each email shows:
   - security_level
   - decrypted_content
   - signature_verified: true (for Levels 2-3)
```

---

## **PHASE 6: ALL SECURITY LEVELS TEST** 🛡️

### ✅ Step 13: Test Level 1 (Quantum Secure)
```bash
1. Set Security Level: 1
2. Send email with subject: "QuMail Test - Level 1 OTP"
3. Console should show: "Algorithm: OTP-QKD-BB84"
4. Should consume a QKD key
```

### ✅ Step 14: Test Level 2 (Quantum-aided AES)
```bash
1. Set Security Level: 2  
2. Send email with subject: "QuMail Test - Level 2 AES"
3. Console should show: "Algorithm: AES-256-GCM-Real-PQC"
4. Should include EdDSA signature
```

### ✅ Step 15: Test Level 3 (Hybrid PQC)
```bash
1. Set Security Level: 3
2. Send email with subject: "QuMail Test - Level 3 PQC"  
3. Console should show: "Algorithm: ML-KEM-768-Real+ML-DSA-65-Real+AES-256-GCM-Real"
4. Should include double signatures (EdDSA + ML-DSA)
```

### ✅ Step 16: Test Level 4 (No Quantum)
```bash
1. Set Security Level: 4
2. Send email with subject: "QuMail Test - Level 4 Classical"
3. Console should show: "Algorithm: AES-256-CBC" 
4. Should show: "Quantum Resistant: false"
```

---

## **PHASE 7: COMPLETE FLOW VERIFICATION** 🔄

### ✅ Step 17: End-to-End Test
```bash
1. Send encrypted email to yourself (any security level)
2. Wait 30 seconds for delivery
3. Use: emailIntegration.receiveQuMailEmails(1)
4. Verify:
   - Email received and detected as QuMail
   - Content decrypted successfully  
   - Original message matches decrypted content
   - Signature verification passed (Levels 2-3)
```

### ✅ Step 18: Performance Test
```bash
1. Send 3 emails quickly with different security levels
2. All should send successfully
3. Check Gmail for all 3 emails
4. Receive and decrypt all 3 emails
5. Verify all content matches
```

---

## **🚨 TROUBLESHOOTING GUIDE**

### Problem: "Email credentials not set"
**Solution:** 
- Click "Gmail Setup" button
- Enter Gmail address and App Password (NOT regular password)
- Make sure App Password is 16 characters with no spaces

### Problem: "SMTP Authentication failed" 
**Solution:**
- Verify 2-Factor Authentication is enabled on Gmail
- Generate new App Password at: https://myaccount.google.com/apppasswords
- Use the new App Password in QuMail

### Problem: "Backend not responding"
**Solution:**
- Check backend is running: http://localhost:5000/
- Restart backend: `python app.py`
- Check no other service is using port 5000

### Problem: "Frontend not loading"
**Solution:**
- Check frontend is running: http://localhost:3000/
- Restart frontend: `npm start` 
- Check no other service is using port 3000

### Problem: "QKD keys not generating"
**Solution:**
- Check browser console for errors
- Try: `window.qkdManager.generateNewQuantumKey()`
- Verify backend QKD API: http://localhost:5000/api/qkd/status

### Problem: "Encryption failing"
**Solution:**
- Check: `window.realEncryption.isApiConnected()`
- Verify backend encryption API: http://localhost:5000/api/encrypt/levels
- Check browser console for detailed errors

---

## **✅ SUCCESS INDICATORS**

When everything is working correctly, you should see:

### 🎯 **Email Sending Success:**
- ✅ Console: "Email sent successfully: [message_id]"
- ✅ Gmail: Encrypted email received with QuMail headers
- ✅ Attachment: qumail_encrypted_content.json present

### 🎯 **Email Receiving Success:** 
- ✅ Console: "Received [X] emails"
- ✅ QuMail emails: Decrypted content visible
- ✅ Signatures: Verified for Levels 2-3

### 🎯 **All Security Levels Working:**
- ✅ Level 1: OTP-QKD-BB84 algorithm
- ✅ Level 2: AES-256-GCM-Real-PQC algorithm  
- ✅ Level 3: ML-KEM-768 + ML-DSA + AES-GCM algorithms
- ✅ Level 4: AES-256-CBC algorithm

### 🎯 **System Integration:**
- ✅ Frontend ↔ Backend communication
- ✅ Real encryption (not mock)
- ✅ Gmail SMTP/IMAP working
- ✅ QKD simulation active
- ✅ All APIs responding

---

## **🏆 DEMO READINESS CHECKLIST**

- [ ] Backend running on localhost:5000
- [ ] Frontend running on localhost:3000
- [ ] Gmail App Password configured
- [ ] All 4 security levels tested
- [ ] Email sending working
- [ ] Email receiving working  
- [ ] QKD keys generating
- [ ] Encryption/decryption working
- [ ] Browser console shows no errors
- [ ] Test emails sent and received successfully

### **🎉 WHEN ALL ITEMS ARE CHECKED:**
**Your QuMail system is ready for the ISRO Smart India Hackathon 2025 demo!** 🚀

---

## **📞 QUICK REFERENCE COMMANDS**

```javascript
// Browser Console Commands for Testing:

// Check email integration status
emailIntegration.isReady()

// Check encryption system status  
window.realEncryption.isApiConnected()

// Generate QKD key
window.qkdManager.generateNewQuantumKey()

// Send test email (after configuring credentials)
emailIntegration.sendTestEmail("recipient@gmail.com", 2)

// Receive emails
emailIntegration.receiveEmails(5)

// Receive only QuMail emails
emailIntegration.receiveQuMailEmails(5)

// Get system capabilities
window.realEncryption.getSystemCapabilities()
```

**🎯 Follow this checklist step-by-step to ensure your QuMail system is fully operational!**

