from fastapi import FastAPI
from soc_environment.env import SOCEnvironment
import uvicorn

app = FastAPI()
env = SOCEnvironment()

@app.post("/reset")
def reset_env():
    state = env.reset()
    return {"status": "success"}

@app.get("/")
def health_check():
    return {"status": "Environment is running"}

def main():
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()