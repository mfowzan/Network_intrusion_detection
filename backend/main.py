from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List
from model import ids_model
import uvicorn
import asyncio
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocket

# ============= APP INITIALIZATION =============

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label"
]


app = FastAPI(
    title="Intrusion Detection System API",
    description="ML-based Network Intrusion Detection System",
    version="1.0.0"
)



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # allow frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


live_clients = []

# SIMULATION CONFIG
SIMULATE_LIVE = True
SIMULATED_INTERVAL = 1.0
SIMULATED_DATA_PATH = "data/KDDTest+.txt"


# ============= REQUEST MODELS =============

class NetworkTraffic(BaseModel):
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: float
    dst_bytes: float
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    hot: int = 0
    num_failed_logins: int = 0
    logged_in: int
    num_compromised: int = 0
    root_shell: int = 0
    su_attempted: int = 0
    num_root: int = 0
    num_file_creations: int = 0
    num_shells: int = 0
    num_access_files: int = 0
    num_outbound_cmds: int = 0
    is_host_login: int = 0
    is_guest_login: int = 0
    count: int
    srv_count: int
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: int
    dst_host_srv_count: int
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float


class PredictionResponse(BaseModel):
    prediction: str
    is_intrusion: bool
    confidence: float
    attack_probability: float
    normal_probability: float


class BatchPredictionRequest(BaseModel):
    traffic_data: List[NetworkTraffic]


class BatchPredictionResponse(BaseModel):
    results: List[PredictionResponse]
    total_count: int
    intrusion_count: int
    normal_count: int


# ============= STARTUP =============

@app.on_event("startup")
async def startup_event():
    try:
        ids_model.load_model()
        print("✓ Model loaded successfully")
    except Exception as e:
        print("✗ Model not loaded:", e)

    if SIMULATE_LIVE:
        asyncio.create_task(simulated_stream_loop())
        print(f"✓ Live simulation enabled ({SIMULATED_DATA_PATH})")


# ============= API ENDPOINTS =============

@app.get("/")
async def root():
    return {"status": "running", "model_loaded": ids_model.is_loaded}


@app.post("/predict", response_model=PredictionResponse)
async def predict_single(traffic: NetworkTraffic):
    if not ids_model.is_loaded:
        raise HTTPException(503, "Model not loaded")

    result = ids_model.predict(traffic.model_dump())
    return result


@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: BatchPredictionRequest):
    if not ids_model.is_loaded:
        raise HTTPException(503, "Model not loaded")

    data_list = [t.model_dump() for t in request.traffic_data]
    results = ids_model.predict_batch(data_list)

    intrusions = sum(r["is_intrusion"] for r in results)
    return {
        "results": results,
        "total_count": len(results),
        "intrusion_count": intrusions,
        "normal_count": len(results) - intrusions
    }


# ============= WEBSOCKET FOR LIVE MODE =============

@app.websocket("/live")
async def live_endpoint(websocket: WebSocket):
    await websocket.accept()   # ✅ This is the missing line

    live_clients.append(websocket)

    try:
        while True:
            # WebSocket keeps running, no receive needed
            await asyncio.sleep(1)
    except:
        live_clients.remove(websocket)



async def send_live_update(message):
    for ws in live_clients:
        try:
            await ws.send_json(message)
        except:
            pass


# ============= SIMULATED LIVE STREAM =============

async def simulated_stream_loop():
    print("Loading dataset for simulated live stream...")

    # Load KDDTest+ in a robust way
    try:
        
        df = pd.read_csv(SIMULATED_DATA_PATH, names=NSL_KDD_COLUMNS)
        df = df.drop(columns=["label"])  # remove label column for live mode

    except:
        print("✗ Could not load dataset for simulation.")
        return

    print(f"✓ Streaming {len(df)} samples in loop")

    while True:
        for _, row in df.iterrows():
            features = ids_model.row_to_features(row)

            # Scale & predict using model
            result = ids_model.predict(features)

            # Send to all websocket dashboard clients
            await send_live_update(result)

            await asyncio.sleep(SIMULATED_INTERVAL)


# ============= RUN =============

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
