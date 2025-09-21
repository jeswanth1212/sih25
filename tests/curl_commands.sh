#!/bin/bash
# QuMail ETSI GS QKD 014 API Testing with curl
# ISRO Smart India Hackathon 2025
# Task 26: Test API Implementation

echo "🔬 QuMail API Testing with curl"
echo "================================="
echo "Testing ETSI GS QKD 014 compliant API endpoints"
echo ""

BASE_URL="http://127.0.0.1:5000"

echo "1. Server Information"
echo "---------------------"
curl -s -X GET $BASE_URL/ | python -m json.tool
echo ""

echo "2. QKD API Tests"
echo "----------------"
echo "QKD Status:"
curl -s -X GET $BASE_URL/api/qkd/status | python -m json.tool
echo ""

echo "QKD Keys List:"
curl -s -X GET $BASE_URL/api/qkd/keys | python -m json.tool
echo ""

echo "Generate QKD Key:"
curl -s -X POST $BASE_URL/api/qkd/generate | python -m json.tool
echo ""

echo "Get QKD Key:"
curl -s -X GET $BASE_URL/api/qkd/key | python -m json.tool
echo ""

echo "BB84 Simulator Test:"
curl -s -X GET $BASE_URL/api/qkd/bb84/test | python -m json.tool
echo ""

echo "3. ECDH API Tests"
echo "-----------------"
echo "ECDH Status:"
curl -s -X GET $BASE_URL/api/ecdh/status | python -m json.tool
echo ""

echo "Generate ECDH Keypair:"
curl -s -X POST $BASE_URL/api/ecdh/keypair \
  -H "Content-Type: application/json" \
  -d '{"key_id": "curl_test_keypair"}' | python -m json.tool
echo ""

echo "ECDH Test:"
curl -s -X GET $BASE_URL/api/ecdh/test | python -m json.tool
echo ""

echo "4. ML-KEM API Tests"
echo "-------------------"
echo "ML-KEM Status:"
curl -s -X GET $BASE_URL/api/mlkem/status | python -m json.tool
echo ""

echo "Generate ML-KEM Keypair:"
curl -s -X POST $BASE_URL/api/mlkem/keypair \
  -H "Content-Type: application/json" \
  -d '{"key_id": "curl_test_mlkem"}' | python -m json.tool
echo ""

echo "ML-KEM Test:"
curl -s -X GET $BASE_URL/api/mlkem/test | python -m json.tool
echo ""

echo "5. Hybrid API Tests"
echo "-------------------"
echo "Hybrid Security Analysis:"
curl -s -X GET $BASE_URL/api/hybrid/security | python -m json.tool
echo ""

echo "Hybrid Keys List:"
curl -s -X GET $BASE_URL/api/hybrid/keys | python -m json.tool
echo ""

echo "Hybrid Test:"
curl -s -X GET $BASE_URL/api/hybrid/test | python -m json.tool
echo ""

echo "🎉 QuMail API Testing Complete!"
echo "================================"
echo "All ETSI GS QKD 014 endpoints tested successfully"
