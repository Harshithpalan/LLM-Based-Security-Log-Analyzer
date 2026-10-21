from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from openai import OpenAI
import os
import json
import re
from datetime import datetime
from typing import List, Dict, Any
from pydantic import BaseModel
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Security Log Analyzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class LogAnalysisRequest(BaseModel):
    logs: str
    log_format: str = "auto"

class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_update(self, message: str, data: Dict = None):
        for connection in self.active_connections:
            try:
                await connection.send_json({
                    "message": message,
                    "data": data,
                    "timestamp": datetime.now().isoformat()
                })
            except:
                pass

manager = WebSocketManager()

def parse_log_line(line: str, log_format: str = "auto") -> Dict[str, Any]:
    """Parse a single log line based on common formats."""
    if not line.strip():
        return None
    
    parsed = {"raw": line.strip()}
    
    # Apache/Nginx Common Log Format
    apache_pattern = r'^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)'
    match = re.match(apache_pattern, line)
    if match:
        parsed.update({
            "ip": match.group(1),
            "timestamp": match.group(2),
            "method": match.group(3),
            "path": match.group(4),
            "protocol": match.group(5),
            "status": int(match.group(6)),
            "size": match.group(7),
            "format": "apache"
        })
        return parsed
    
    # Syslog format
    syslog_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (\S+) (\S+): (.*)$'
    match = re.match(syslog_pattern, line)
    if match:
        parsed.update({
            "timestamp": match.group(1),
            "hostname": match.group(2),
            "process": match.group(3),
            "message": match.group(4),
            "format": "syslog"
        })
        return parsed
    
    # JSON format
    try:
        json_data = json.loads(line)
        parsed.update({
            "json_data": json_data,
            "format": "json"
        })
        return parsed
    except:
        pass
    
    # Generic parsing
    parsed.update({
        "format": "generic",
        "timestamp": datetime.now().isoformat()
    })
    return parsed

def detect_anomalies(logs: List[Dict]) -> List[Dict]:
    """Basic anomaly detection before LLM analysis."""
    anomalies = []
    
    for log in logs:
        if log and "status" in log:
            # HTTP error codes
            if log["status"] >= 400:
                anomalies.append({
                    "log": log,
                    "type": "http_error",
                    "severity": "high" if log["status"] >= 500 else "medium"
                })
        
        if log and "message" in log:
            msg = log["message"].lower()
            if any(keyword in msg for keyword in ["failed", "error", "denied", "unauthorized", "attack"]):
                anomalies.append({
                    "log": log,
                    "type": "security_event",
                    "severity": "high"
                })
    
    return anomalies

async def analyze_with_llm(logs: List[Dict], websocket_manager: WebSocketManager = None) -> Dict:
    """Analyze logs using OpenAI."""
    await websocket_manager.send_update("Preparing logs for analysis...")
    
    # Sample logs if too many
    sample_size = min(100, len(logs))
    sample_logs = logs[:sample_size]
    
    log_text = "\n".join([json.dumps(log, indent=2) for log in sample_logs])
    
    await websocket_manager.send_update("Sending to LLM for analysis...")
    
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": """You are a security log analyst. Analyze the provided logs and identify:
1. Security threats or attacks
2. Suspicious patterns
3. Anomalies
4. Recommendations

Respond in JSON format with this structure:
{
    "summary": "Brief overview",
    "threats": [{"type": "threat type", "severity": "high/medium/low", "description": "details", "affected_ips": ["ip1", "ip2"]}],
    "patterns": [{"pattern": "description", "count": number}],
    "recommendations": ["action item 1", "action item 2"],
    "risk_score": 0-100
}"""
                },
                {
                    "role": "user",
                    "content": f"Analyze these security logs:\n\n{log_text}"
                }
            ],
            temperature=0.3,
            max_tokens=2000
        )
        
        await websocket_manager.send_update("Processing LLM response...")
        
        result = json.loads(response.choices[0].message.content)
        result["total_logs_analyzed"] = len(logs)
        result["sample_size"] = sample_size
        
        return result
        
    except Exception as e:
        logger.error(f"LLM analysis error: {e}")
        return {
            "error": str(e),
            "summary": "Analysis failed",
            "threats": [],
            "patterns": [],
            "recommendations": [],
            "risk_score": 0
        }

@app.get("/")
async def root():
    return {"message": "Security Log Analyzer API"}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/analyze")
async def analyze_logs(request: LogAnalysisRequest):
    """Analyze logs (non-streaming)."""
    try:
        lines = request.logs.strip().split('\n')
        parsed_logs = [parse_log_line(line, request.log_format) for line in lines]
        parsed_logs = [log for log in parsed_logs if log is not None]
        
        # Basic anomaly detection
        anomalies = detect_anomalies(parsed_logs)
        
        # LLM analysis
        analysis = await analyze_with_llm(parsed_logs, manager)
        
        return {
            "parsed_logs": parsed_logs,
            "anomalies": anomalies,
            "analysis": analysis
        }
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.websocket("/ws/analyze")
async def websocket_analyze(websocket: WebSocket):
    """Real-time log analysis via WebSocket."""
    await manager.connect(websocket)
    try:
        data = await websocket.receive_json()
        logs = data.get("logs", "")
        log_format = data.get("log_format", "auto")
        
        await manager.send_update("Parsing logs...")
        
        lines = logs.strip().split('\n')
        parsed_logs = []
        
        for i, line in enumerate(lines):
            if i % 100 == 0:
                await manager.send_update(f"Parsing log {i+1}/{len(lines)}...", {"progress": i/len(lines)})
            parsed = parse_log_line(line, log_format)
            if parsed:
                parsed_logs.append(parsed)
        
        await manager.send_update(f"Parsed {len(parsed_logs)} logs")
        
        # Basic anomaly detection
        await manager.send_update("Detecting anomalies...")
        anomalies = detect_anomalies(parsed_logs)
        await manager.send_update(f"Found {len(anomalies)} potential anomalies")
        
        # LLM analysis
        analysis = await analyze_with_llm(parsed_logs, manager)
        
        await manager.send_update("Analysis complete", {
            "result": {
                "parsed_logs": parsed_logs,
                "anomalies": anomalies,
                "analysis": analysis
            }
        })
        
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.send_update(f"Error: {str(e)}")
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
