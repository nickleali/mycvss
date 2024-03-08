from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
import kev_checkapi
import score_checkapi
import score_modifierapi

app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:8888",
    "http://127.0.0.1:8888",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(kev_checkapi.router, prefix="/kev_checkapi")
app.include_router(score_checkapi.router, prefix="/score_checkapi")
app.include_router(score_modifierapi.router, prefix="/score_modifierapi")

@app.get("/mycvss/")
async def read_string(cve: str | None = None, vector_string: str | None = None):
    if cve and vector_string:
        return {"cve_id": cve, "vector_string": vector_string}
    if cve:
        return {"cve_id": cve}
    if vector_string:
        return {"vector_string": vector_string}
    else:
        return {"cve_id": False, "vector_string": False}
