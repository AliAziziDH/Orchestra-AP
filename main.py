from fastapi import FastAPI

app = FastAPI(title="Orchestra API")


@app.get("/")
def root():
    return {"service": "orchestra-api", "status": "up"}


@app.get("/healthz")
def healthz():
    return {"ok": True}
