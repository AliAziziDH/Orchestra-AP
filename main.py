from fastapi import FastAPI

app = FastAPI(title="Orchestra API")


@app.get("/")
def root():
    return {"service": "orchestra-api", "status": "up"}


@app.get("/health")
def health():
    return {"ok": True}
