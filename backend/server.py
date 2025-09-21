from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can replace "*" with your Vercel frontend domain for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "Backend is running on Vercel 🚀"}


# Example route
@app.get("/api/hello")
async def hello():
    return {"message": "Hello from FastAPI backend!"}
