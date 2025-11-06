from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from model import ids_model
import uvicorn

# Initialize FastAPI app
app = FastAPI(
    title="Intrusion Detection System API",
    description="ML-based Network Intrusion Detection System",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class NetworkTraffic(BaseModel):
    """Network traffic data model"""
    duration: float = Field(..., description="Connection duration")
    protocol_type: str = Field(..., description="Protocol type (tcp, udp, icmp)")
    service: str = Field(..., description="Network service (http, ftp, smtp, etc.)")
    flag: str = Field(..., description="Connection status flag")
    src_bytes: float = Field(..., description="Bytes sent from source")
    dst_bytes: float = Field(..., description="Bytes sent to destination")
    land: int = Field(default=0, description="1 if connection is from/to same host/port")
    wrong_fragment: int = Field(default=0, description="Number of wrong fragments")
    urgent: int = Field(default=0, description="Number of urgent packets")
    hot: int = Field(default=0, description="Number of hot indicators")
    num_failed_logins: int = Field(default=0, description="Number of failed login attempts")
    logged_in: int = Field(..., description="1 if successfully logged in, 0 otherwise")
    num_compromised: int = Field(default=0, description="Number of compromised conditions")
    root_shell: int = Field(default=0, description="1 if root shell obtained")
    su_attempted: int = Field(default=0, description="1 if su root attempted")
    num_root: int = Field(default=0, description="Number of root accesses")
    num_file_creations: int = Field(default=0, description="Number of file creation operations")
    num_shells: int = Field(default=0, description="Number of shell prompts")
    num_access_files: int = Field(default=0, description="Number of access file operations")
    num_outbound_cmds: int = Field(default=0, description="Number of outbound commands")
    is_host_login: int = Field(default=0, description="1 if host login")
    is_guest_login: int = Field(default=0, description="1 if guest login")
    count: int = Field(..., description="Number of connections to same host")
    srv_count: int = Field(..., description="Number of connections to same service")
    serror_rate: float = Field(..., description="SYN error rate")
    srv_serror_rate: float = Field(..., description="Service SYN error rate")
    rerror_rate: float = Field(..., description="REJ error rate")
    srv_rerror_rate: float = Field(..., description="Service REJ error rate")
    same_srv_rate: float = Field(..., description="Same service rate")
    diff_srv_rate: float = Field(..., description="Different service rate")
    srv_diff_host_rate: float = Field(..., description="Service different host rate")
    dst_host_count: int = Field(..., description="Destination host count")
    dst_host_srv_count: int = Field(..., description="Destination host service count")
    dst_host_same_srv_rate: float = Field(..., description="Destination host same service rate")
    dst_host_diff_srv_rate: float = Field(..., description="Destination host different service rate")
    dst_host_same_src_port_rate: float = Field(..., description="Destination host same source port rate")
    dst_host_srv_diff_host_rate: float = Field(..., description="Destination host service different host rate")
    dst_host_serror_rate: float = Field(..., description="Destination host SYN error rate")
    dst_host_srv_serror_rate: float = Field(..., description="Destination host service SYN error rate")
    dst_host_rerror_rate: float = Field(..., description="Destination host REJ error rate")
    dst_host_srv_rerror_rate: float = Field(..., description="Destination host service REJ error rate")

    class Config:
        json_schema_extra = {
            "example": {
                "duration": 0,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 181,
                "dst_bytes": 5450,
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 0,
                "num_failed_logins": 0,
                "logged_in": 1,
                "num_compromised": 0,
                "root_shell": 0,
                "su_attempted": 0,
                "num_root": 0,
                "num_file_creations": 0,
                "num_shells": 0,
                "num_access_files": 0,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": 8,
                "srv_count": 8,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "srv_diff_host_rate": 0.0,
                "dst_host_count": 9,
                "dst_host_srv_count": 9,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0,
                "dst_host_same_src_port_rate": 0.11,
                "dst_host_srv_diff_host_rate": 0.0,
                "dst_host_serror_rate": 0.0,
                "dst_host_srv_serror_rate": 0.0,
                "dst_host_rerror_rate": 0.0,
                "dst_host_srv_rerror_rate": 0.0
            }
        }

class PredictionResponse(BaseModel):
    """Response model for predictions"""
    prediction: str
    is_intrusion: bool
    confidence: float
    attack_probability: float
    normal_probability: float

class BatchPredictionRequest(BaseModel):
    """Request model for batch predictions"""
    traffic_data: List[NetworkTraffic]

class BatchPredictionResponse(BaseModel):
    """Response model for batch predictions"""
    results: List[PredictionResponse]
    total_count: int
    intrusion_count: int
    normal_count: int

# Startup event
@app.on_event("startup")
async def startup_event():
    """Load model on startup"""
    try:
        ids_model.load_model()
        print("✓ Model loaded successfully")
    except Exception as e:
        print(f"✗ Error loading model: {str(e)}")
        print("Please train the model first by running: python train_model.py")

# API Routes
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Intrusion Detection System API",
        "status": "running",
        "model_loaded": ids_model.is_loaded
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": ids_model.is_loaded
    }

@app.post("/predict", response_model=PredictionResponse)
async def predict_intrusion(traffic: NetworkTraffic):
    """
    Predict if network traffic is an intrusion or normal
    
    Args:
        traffic: Network traffic features
        
    Returns:
        Prediction result with confidence scores
    """
    try:
        if not ids_model.is_loaded:
            raise HTTPException(
                status_code=503,
                detail="Model not loaded. Please train the model first."
            )
        
        # Convert Pydantic model to dict
        traffic_data = traffic.model_dump()
        
        # Make prediction
        result = ids_model.predict(traffic_data)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: BatchPredictionRequest):
    """
    Predict multiple network traffic instances
    
    Args:
        request: Batch of network traffic data
        
    Returns:
        Batch prediction results with statistics
    """
    try:
        if not ids_model.is_loaded:
            raise HTTPException(
                status_code=503,
                detail="Model not loaded. Please train the model first."
            )
        
        # Convert Pydantic models to dicts
        traffic_data_list = [traffic.model_dump() for traffic in request.traffic_data]
        
        # Make predictions
        results = ids_model.predict_batch(traffic_data_list)
        
        # Calculate statistics
        intrusion_count = sum(1 for r in results if r['is_intrusion'])
        normal_count = len(results) - intrusion_count
        
        return {
            "results": results,
            "total_count": len(results),
            "intrusion_count": intrusion_count,
            "normal_count": normal_count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/model/info")
async def model_info():
    """Get model information"""
    if not ids_model.is_loaded:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please train the model first."
        )
    
    return {
        "model_type": "XGBoost Classifier",
        "features_count": len(ids_model.feature_names) if ids_model.feature_names else 0,
        "is_loaded": ids_model.is_loaded,
        "classes": ["Normal", "Attack"]
    }

# Run the application
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )