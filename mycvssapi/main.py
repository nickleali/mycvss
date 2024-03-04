from fastapi import Depends, FastAPI
import kev_checkapi

app = FastAPI()

app.include_router(kev_checkapi.router, prefix="/kev_checkapi")

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
