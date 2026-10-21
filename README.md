# LLM-Based Security Log Analyzer

A web application that uses AI (OpenAI) to analyze security logs and detect threats, anomalies, and patterns.

## Features

- **Multiple Log Format Support**: Apache/Nginx, Syslog, JSON, and generic log formats
- **AI-Powered Analysis**: Uses OpenAI GPT-4 for intelligent log analysis
- **Real-time Progress**: WebSocket support for live analysis updates
- **Threat Detection**: Identifies security threats with severity levels
- **Pattern Recognition**: Detects suspicious patterns in logs
- **Actionable Recommendations**: Provides security recommendations based on analysis
- **Risk Scoring**: Calculates overall risk score (0-100)

## Tech Stack

### Backend
- FastAPI (Python)
- OpenAI API
- WebSocket for real-time updates
- Pydantic for data validation

### Frontend
- React (with Vite)
- Axios for API calls
- WebSocket client
- Modern CSS with gradient design

## Prerequisites

- Python 3.8+
- Node.js 16+
- OpenAI API key

## Setup

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file with your OpenAI API key
echo "OPENAI_API_KEY=your_api_key_here" > .env
```

### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install
```

## Running the Application

### Start Backend

```bash
cd backend
# Activate virtual environment if not already active
python main.py
```

The backend will run on `http://localhost:8000`

### Start Frontend

```bash
cd frontend
npm run dev
```

The frontend will run on `http://localhost:5173`

## Usage

1. Open your browser and navigate to `http://localhost:5173`
2. Either:
   - Upload a log file (.log, .txt, or .json)
   - Or paste logs directly into the text area
3. Select the log format (or leave as "Auto-detect")
4. Click "Analyze Logs"
5. View the analysis results including:
   - Summary and risk score
   - Detected threats with severity levels
   - Patterns found in logs
   - Security recommendations
   - Detailed anomalies

## Supported Log Formats

### Apache/Nginx Common Log Format
```
192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 1234
```

### Syslog Format
```
Oct 21 08:15:30 server1 sshd[1234]: Failed password for root from 192.168.1.100
```

### JSON Format
```json
{"timestamp": "2023-10-21T08:15:30Z", "level": "ERROR", "message": "Authentication failed", "ip": "192.168.1.100"}
```

### Generic Format
Any text-based log format will be parsed generically.

## API Endpoints

### POST /analyze
Analyze logs via REST API
- Body: `{"logs": "log content", "log_format": "auto"}`
- Returns: Analysis results

### WebSocket /ws/analyze
Real-time log analysis
- Send: `{"logs": "log content", "log_format": "auto"}`
- Receive: Progress updates and final results

### GET /health
Health check endpoint

## Security Notes

- Never commit your `.env` file with API keys
- The application sends log data to OpenAI for analysis
- Ensure your OpenAI API key has appropriate permissions
- Consider implementing rate limiting for production use

## Customization

### Adding New Log Parsers
Edit `backend/main.py` and add new patterns to the `parse_log_line` function.

### Modifying LLM Prompts
Edit the system prompt in the `analyze_with_llm` function to customize analysis behavior.

### Changing the Model
Modify the `model` parameter in the OpenAI API call (e.g., change from "gpt-4" to "gpt-3.5-turbo").

## Troubleshooting

### CORS Errors
Ensure the backend CORS middleware includes your frontend URL.

### WebSocket Connection Failed
The app will automatically fall back to REST API if WebSocket fails.

### OpenAI API Errors
- Verify your API key is correct
- Check your OpenAI account has credits
- Ensure you have access to the specified model

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
