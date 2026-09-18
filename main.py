from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from database import SessionLocal, Project
from agent import handle_forensics_query

app = FastAPI(title="AI Memory Forensics Assistant")

# Pydantic schemas for API requests
class ProjectCreate(BaseModel):
    name: str
    dump_path: str

class ChatRequest(BaseModel):
    project_id: int
    query: str

@app.post("/projects/")
def create_project(project: ProjectCreate):
    db = SessionLocal()
    db_project = Project(name=project.name, dump_path=project.dump_path)
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    db.close()
    return {"message": "Project created successfully", "project_id": db_project.id}

@app.post("/chat/")
def chat_with_assistant(request: ChatRequest):
    # This will trigger the agent reasoning loop and execute vol3 if necessary
    response = handle_forensics_query(request.project_id, request.query)
    return {"agent_response": response}
