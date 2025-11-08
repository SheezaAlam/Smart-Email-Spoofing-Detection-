# PhishShield: Smart Email Spoofing Detection and Analysis Dashboard

## Introduction
PhishShield is a smart email spoofing detection system designed to identify suspicious and spoofed emails through email header analysis. The system helps users and cybersecurity professionals verify the authenticity of emails and prevent phishing attacks. It provides a live dashboard that visualizes real-time detection results, authentication checks, and analysis summaries.

## Overview
The project focuses on detecting spoofed emails using metadata embedded within email headers. These headers contain authentication data such as SPF, DKIM, and DMARC, along with information about the sender domain, return path, and routing servers.

We developed a Flask-based web application that allows users to upload or paste raw email headers. The system automatically parses the header into structured data, performs authentication checks, and classifies the email as Legitimate, Possibly Spoofed, or Suspicious.

The project also includes a smart dashboard that provides an analytical view of the results, displaying success rates, total analyses, verdict counts, and recent reports.

## Motivation
Email spoofing is a common entry point for phishing attacks and social engineering campaigns. Attackers often forge sender addresses to trick users into sharing sensitive information or clicking malicious links.

Our motivation was to build a user-friendly yet technically deep system that demonstrates how cybersecurity tools like MXToolbox perform header analysis. This project provides insights into programmatically detecting spoofing by examining authentication mechanisms and header anomalies.

## Methodologies

### 1. Email Header Parsing
The system extracts and analyzes important fields such as:
- From
- Return-Path
- Received
- Authentication-Results
- SPF, DKIM, and DMARC indicators

A Python-based parser reads the raw text, identifies relevant lines, and separates key-value pairs for further analysis.

### 2. Authentication Analysis
Parsed data is evaluated for:
- **SPF (Sender Policy Framework):** Verifies if the sending IP is authorized for the sender’s domain.
- **DKIM (DomainKeys Identified Mail):** Confirms message content integrity.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** Checks domain alignment and policy compliance.
- **Return-Path Validation:** Ensures the return path matches the sender domain.
- **Keyword Scanning:** Detects phishing-related terms.
- **Attachment Inspection:** Flags risky file types (.exe, .scr, etc.).

Each test outputs a pass, fail, or neutral result, and a confidence score is calculated based on these outcomes.

### 3. Verdict Generation
Scores are weighted as follows:
- **High scores (80–100%) → Legitimate**
- **Medium scores (50–79%) → Possibly Spoofed**
- **Low scores (0–49%) → Suspicious**

Verdicts are displayed with timestamps and stored in the database for historical review.

### 4. Smart Dashboard
The dashboard visualizes key metrics:
- Total Emails Analyzed
- SPF, DKIM, and DMARC Success Rates
- Authentication Success Breakdown
- Verdict Distribution
- Recent Analyses Table

Each record includes the email subject, verdict, confidence score, and analysis time. Users can view detailed reports for specific analyses.

### 5. Detailed Report View
Individual reports show:
- Subject and timestamp
- Overall verdict and score
- Recommended action (e.g., "Be careful — verify sender")
- Detailed check results for SPF, DKIM, DMARC, Return-Path, Keywords, Attachments
- Explanations for failed or uncertain checks

This helps users understand why an email is classified as spoofed or legitimate.

## End Result
PhishShield provides:
- A fully functional Flask web interface for analyzing email headers.
- A real-time dashboard showing all analysis results and verdict statistics.
- Detailed reports explaining every authentication check.
- A secure and educational environment for understanding email spoofing detection.

Sample dashboard metrics:
- SPF Success: 65.4%
- DKIM Success: 65.4%
- DMARC Success: 53.8%

The system accurately identifies spoofed and legitimate emails with clarity.

## What We Have Learned
- Email header structure and spoofing techniques.
- Role of SPF, DKIM, and DMARC in preventing email forgery.
- Parsing complex text-based headers into structured Python data.
- Building Flask applications with templates and dashboards.
- Interpreting and visualizing email authentication results.
- Designing intuitive interfaces for both technical and non-technical users.

## Conclusion
PhishShield demonstrates email spoofing detection using header-based analysis. By breaking down authentication data, scanning for phishing indicators, and presenting visual insights, the tool bridges cybersecurity education and practical application. This project strengthened our understanding of email security, authentication protocols, and real-time web visualization.

## Project Files
- Flask application scripts
- Templates for web interface
- Static files (CSS, JS)
- Sample email headers for testing
- SQLite database for storing results
- Requirements file (`requirements.txt`)
