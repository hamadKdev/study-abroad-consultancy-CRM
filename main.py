import os
import requests
from uuid import uuid4
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Query,
    BackgroundTasks,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import supabase
from auth import hash_password, verify_password, create_token, decode_token

from models import (
    SignupData,
    LoginData,
    LeadData,
    LeadStageData,
    FollowUpData,
    FollowUpUpdate,
    UniversityData,
    ProgramData,
    ProgramDocumentData,
    ApplicationData,
    ApplicationStatusData,
    DocumentStatusData,
    NoteData,
)

load_dotenv()

# =========================================================
# APP
# =========================================================

app = FastAPI(
    title="Study Abroad Consultancy CRM API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL")
STORAGE_BUCKET = os.getenv(
    "SUPABASE_STORAGE_BUCKET",
    "documents"
)


# =========================================================
# N8N WEBHOOK
# =========================================================

def send_n8n_webhook(event_type: str, data: dict):
    """
    Sends CRM event data to n8n.

    If n8n is unavailable, the main API operation
    will still continue.
    """

    if not N8N_WEBHOOK_URL:
        print("N8N_WEBHOOK_URL is not configured.")
        return

    payload = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data
    }

    try:
        response = requests.post(
            N8N_WEBHOOK_URL,
            json=payload,
            timeout=10
        )

        print(
            f"n8n webhook: {event_type} "
            f"-> {response.status_code}"
        )

    except Exception as e:
        print(
            f"n8n webhook failed for {event_type}: {e}"
        )


# =========================================================
# AUTH HELPERS
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = decode_token(token)

        user_id = payload.get("user_id")
        role = payload.get("role")

        if not user_id or not role:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        result = (
            supabase
            .table("users")
            .select("*")
            .eq("id", user_id)
            .single()
            .execute()
        )

        user = result.data

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found"
            )

        if not user.get("is_active", True):
            raise HTTPException(
                status_code=403,
                detail="User account is inactive"
            )

        return user

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


def require_roles(*allowed_roles):

    def checker(
        current_user=Depends(get_current_user)
    ):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission"
            )

        return current_user

    return checker


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    return {
        "message": "Study Abroad Consultancy CRM API",
        "status": "running",
        "n8n_webhook": bool(N8N_WEBHOOK_URL)
    }


# =========================================================
# AUTH
# =========================================================

@app.post("/auth/signup")
def signup(data: SignupData):

    # Public signup should create students only
    role = "student"

    existing = (
        supabase
        .table("users")
        .select("id")
        .eq("email", str(data.email).lower())
        .execute()
    )

    if existing.data:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    user = {
        "full_name": data.full_name,
        "email": str(data.email).lower(),
        "phone": data.phone,
        "password_hash": hash_password(data.password),
        "role": role,
        "is_active": True
    }

    result = (
        supabase
        .table("users")
        .insert(user)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=500,
            detail="User registration failed"
        )

    created_user = result.data[0]

    return {
        "message": "Signup successful",
        "user": {
            "id": created_user["id"],
            "full_name": created_user["full_name"],
            "email": created_user["email"],
            "role": created_user["role"]
        }
    }


@app.post("/auth/login")
def login(data: LoginData):

    result = (
        supabase
        .table("users")
        .select("*")
        .eq("email", str(data.email).lower())
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    user = result.data[0]

    if not verify_password(
        data.password,
        user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )

    token = create_token(
        user["id"],
        user["role"]
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "user_id": user["id"],
        "full_name": user["full_name"]
    }


@app.get("/auth/me")
def me(
    current_user=Depends(get_current_user)
):
    user = dict(current_user)

    user.pop("password_hash", None)

    return user


# =========================================================
# USERS
# =========================================================

@app.get("/users")
def get_users(
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("users")
        .select(
            "id,full_name,email,phone,role,is_active,created_at"
        )
        .order("created_at", desc=True)
        .execute()
    )

    return result.data


@app.patch("/users/{user_id}/status")
def update_user_status(
    user_id: str,
    is_active: bool,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("users")
        .update({
            "is_active": is_active
        })
        .eq("id", user_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return result.data[0]


# =========================================================
# LEADS
# =========================================================

@app.post("/leads")
def create_lead(
    data: LeadData,
    background_tasks: BackgroundTasks,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    lead = data.model_dump()

    if current_user["role"] == "counselor":
        lead["counselor_id"] = current_user["id"]

    lead["email"] = str(data.email).lower()

    result = (
        supabase
        .table("leads")
        .insert(lead)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=400,
            detail="Lead creation failed"
        )

    created_lead = result.data[0]

    background_tasks.add_task(
        send_n8n_webhook,
        "lead_created",
        created_lead
    )

    return {
        "message": "Lead created successfully",
        "lead": created_lead
    }


@app.get("/leads")
def get_leads(
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    query = (
        supabase
        .table("leads")
        .select("*")
    )

    if current_user["role"] == "counselor":
        query = query.eq(
            "counselor_id",
            current_user["id"]
        )

    result = (
        query
        .order("created_at", desc=True)
        .execute()
    )

    return result.data


@app.get("/leads/{lead_id}")
def get_lead(
    lead_id: str,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    result = (
        supabase
        .table("leads")
        .select("*")
        .eq("id", lead_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Lead not found"
        )

    lead = result.data[0]

    if (
        current_user["role"] == "counselor"
        and lead.get("counselor_id") != current_user["id"]
    ):
        raise HTTPException(
            status_code=403,
            detail="You cannot access this lead"
        )

    return lead


@app.put("/leads/{lead_id}")
def update_lead(
    lead_id: str,
    data: LeadData,
    background_tasks: BackgroundTasks,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    old_result = (
        supabase
        .table("leads")
        .select("*")
        .eq("id", lead_id)
        .execute()
    )

    if not old_result.data:
        raise HTTPException(
            status_code=404,
            detail="Lead not found"
        )

    old_lead = old_result.data[0]

    if (
        current_user["role"] == "counselor"
        and old_lead.get("counselor_id") != current_user["id"]
    ):
        raise HTTPException(
            status_code=403,
            detail="You cannot update this lead"
        )

    lead = data.model_dump()
    lead["email"] = str(data.email).lower()

    if current_user["role"] == "counselor":
        lead["counselor_id"] = current_user["id"]

    result = (
        supabase
        .table("leads")
        .update(lead)
        .eq("id", lead_id)
        .execute()
    )

    return result.data[0]


@app.patch("/leads/{lead_id}/stage")
def change_lead_stage(
    lead_id: str,
    data: LeadStageData,
    background_tasks: BackgroundTasks,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    old_result = (
        supabase
        .table("leads")
        .select("*")
        .eq("id", lead_id)
        .execute()
    )

    if not old_result.data:
        raise HTTPException(
            status_code=404,
            detail="Lead not found"
        )

    lead = old_result.data[0]

    if (
        current_user["role"] == "counselor"
        and lead.get("counselor_id") != current_user["id"]
    ):
        raise HTTPException(
            status_code=403,
            detail="You cannot update this lead"
        )

    update_data = {
        "stage": data.stage
    }

    if data.stage == "Lost":
        update_data["lost_reason"] = data.lost_reason
    else:
        update_data["lost_reason"] = None

    result = (
        supabase
        .table("leads")
        .update(update_data)
        .eq("id", lead_id)
        .execute()
    )

    updated_lead = result.data[0]

    background_tasks.add_task(
        send_n8n_webhook,
        "lead_stage_changed",
        {
            "lead": updated_lead,
            "old_stage": lead.get("stage"),
            "new_stage": data.stage
        }
    )

    return updated_lead


@app.delete("/leads/{lead_id}")
def delete_lead(
    lead_id: str,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("leads")
        .delete()
        .eq("id", lead_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Lead not found"
        )

    return {
        "message": "Lead deleted successfully"
    }


# =========================================================
# FOLLOW UPS
# =========================================================

@app.post("/follow-ups")
def create_follow_up(
    data: FollowUpData,
    background_tasks: BackgroundTasks,
    current_user=Depends(require_roles("admin", "counselor"))
):
    follow_up = data.model_dump(mode="json")

    if current_user["role"] == "counselor":
        follow_up["counselor_id"] = current_user["id"]

    result = (
        supabase
        .table("follow_ups")
        .insert(follow_up)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=400,
            detail="Follow-up creation failed"
        )

    created_follow_up = result.data[0]

    background_tasks.add_task(
        send_n8n_webhook,
        "follow_up_created",
        {
            "id": created_follow_up["id"],
            "lead_id": created_follow_up["lead_id"],
            "counselor_id": created_follow_up["counselor_id"],
            "task": created_follow_up["task"],
            "due_date": data.due_date.isoformat(),
            "completed": created_follow_up.get("completed", False)
        }
    )

    return created_follow_up


@app.get("/follow-ups")
def get_follow_ups(
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    query = (
        supabase
        .table("follow_ups")
        .select("*")
    )

    if current_user["role"] == "counselor":
        query = query.eq(
            "counselor_id",
            current_user["id"]
        )

    result = (
        query
        .order("due_date")
        .execute()
    )

    return result.data


@app.patch("/follow-ups/{follow_up_id}")
def update_follow_up(
    follow_up_id: str,
    data: FollowUpUpdate,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    result = (
        supabase
        .table("follow_ups")
        .update(data.model_dump())
        .eq("id", follow_up_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Follow-up not found"
        )

    return result.data[0]


@app.delete("/follow-ups/{follow_up_id}")
def delete_follow_up(
    follow_up_id: str,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    result = (
        supabase
        .table("follow_ups")
        .delete()
        .eq("id", follow_up_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Follow-up not found"
        )

    return {
        "message": "Follow-up deleted successfully"
    }


# =========================================================
# UNIVERSITIES
# =========================================================

@app.post("/universities")
def create_university(
    data: UniversityData,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("universities")
        .insert(data.model_dump())
        .execute()
    )

    return result.data[0]


@app.get("/universities")
def get_universities(
    current_user=Depends(get_current_user)
):

    result = (
        supabase
        .table("universities")
        .select("*")
        .order("created_at", desc=True)
        .execute()
    )

    return result.data


@app.get("/universities/{university_id}")
def get_university(
    university_id: str,
    current_user=Depends(get_current_user)
):

    result = (
        supabase
        .table("universities")
        .select("*")
        .eq("id", university_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="University not found"
        )

    return result.data[0]


@app.put("/universities/{university_id}")
def update_university(
    university_id: str,
    data: UniversityData,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("universities")
        .update(data.model_dump())
        .eq("id", university_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="University not found"
        )

    return result.data[0]


@app.delete("/universities/{university_id}")
def delete_university(
    university_id: str,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("universities")
        .delete()
        .eq("id", university_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="University not found"
        )

    return {
        "message": "University deleted successfully"
    }


# =========================================================
# PROGRAMS
# =========================================================

@app.post("/programs")
def create_program(
    data: ProgramData,
    current_user=Depends(
        require_roles("admin")
    )
):
    result = (
        supabase
        .table("programs")
        .insert(data.model_dump(mode="json"))
        .execute()
    )

    return result.data[0]

@app.get("/programs")
def get_programs(
    university_id: str | None = Query(None),
    current_user=Depends(get_current_user)
):

    query = (
        supabase
        .table("programs")
        .select("*")
    )

    if university_id:
        query = query.eq(
            "university_id",
            university_id
        )

    result = (
        query
        .order("created_at", desc=True)
        .execute()
    )

    return result.data


@app.get("/programs/{program_id}")
def get_program(
    program_id: str,
    current_user=Depends(get_current_user)
):

    result = (
        supabase
        .table("programs")
        .select("*")
        .eq("id", program_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    return result.data[0]


@app.put("/programs/{program_id}")
def update_program(
    program_id: str,
    data: ProgramData,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("programs")
        .update(data.model_dump(mode="json"))
        .eq("id", program_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    return result.data[0]



@app.delete("/programs/{program_id}")
def delete_program(
    program_id: str,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("programs")
        .delete()
        .eq("id", program_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    return {
        "message": "Program deleted successfully"
    }


# =========================================================
# PROGRAM DOCUMENTS
# =========================================================

@app.post("/program-documents")
def create_program_document(
    data: ProgramDocumentData,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("program_documents")
        .insert(data.model_dump())
        .execute()
    )

    return result.data[0]


@app.get("/program-documents")
def get_program_documents(
    program_id: str | None = Query(None),
    current_user=Depends(get_current_user)
):

    query = (
        supabase
        .table("program_documents")
        .select("*")
    )

    if program_id:
        query = query.eq(
            "program_id",
            program_id
        )

    result = query.execute()

    return result.data


@app.put("/program-documents/{document_id}")
def update_program_document(
    document_id: str,
    data: ProgramDocumentData,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("program_documents")
        .update(data.model_dump())
        .eq("id", document_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Program document not found"
        )

    return result.data[0]


@app.delete("/program-documents/{document_id}")
def delete_program_document(
    document_id: str,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("program_documents")
        .delete()
        .eq("id", document_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Program document not found"
        )

    return {
        "message": "Program document deleted successfully"
    }


# =========================================================
# APPLICATIONS
# =========================================================

@app.post("/applications")
def create_application(
    data: ApplicationData,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user)
):

    application = data.model_dump()

    if current_user["role"] == "student":
        application["student_id"] = current_user["id"]

    result = (
        supabase
        .table("applications")
        .insert(application)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=400,
            detail="Application creation failed"
        )

    created_application = result.data[0]

    background_tasks.add_task(
        send_n8n_webhook,
        "application_created",
        created_application
    )

    return {
        "message": "Application created successfully",
        "application": created_application
    }


@app.get("/applications")
def get_applications(
    current_user=Depends(get_current_user)
):

    query = (
        supabase
        .table("applications")
        .select("*")
    )

    if current_user["role"] == "student":
        query = query.eq(
            "student_id",
            current_user["id"]
        )

    result = (
        query
        .order("created_at", desc=True)
        .execute()
    )

    return result.data


@app.get("/applications/{application_id}")
def get_application(
    application_id: str,
    current_user=Depends(get_current_user)
):

    result = (
        supabase
        .table("applications")
        .select("*")
        .eq("id", application_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    application = result.data[0]

    if (
        current_user["role"] == "student"
        and application["student_id"] != current_user["id"]
    ):
        raise HTTPException(
            status_code=403,
            detail="You cannot access this application"
        )

    return application


@app.patch("/applications/{application_id}/status")
def update_application_status(
    application_id: str,
    data: ApplicationStatusData,
    background_tasks: BackgroundTasks,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    old_result = (
        supabase
        .table("applications")
        .select("*")
        .eq("id", application_id)
        .execute()
    )

    if not old_result.data:
        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    old_application = old_result.data[0]

    update_data = {
        "status": data.status,
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat()
    }

    result = (
        supabase
        .table("applications")
        .update(update_data)
        .eq("id", application_id)
        .execute()
    )

    updated_application = result.data[0]

    background_tasks.add_task(
        send_n8n_webhook,
        "application_status_changed",
        {
            "application": updated_application,
            "old_status": old_application.get("status"),
            "new_status": data.status
        }
    )

    return updated_application


@app.delete("/applications/{application_id}")
def delete_application(
    application_id: str,
    current_user=Depends(
        require_roles("admin")
    )
):

    result = (
        supabase
        .table("applications")
        .delete()
        .eq("id", application_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    return {
        "message": "Application deleted successfully"
    }


@app.post("/applications/{application_id}/documents")
def upload_document(
    application_id: str,
    program_document_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user=Depends(get_current_user)
):

    # =====================================================
    # 1. CHECK APPLICATION
    # =====================================================

    application_result = (
        supabase
        .table("applications")
        .select("*")
        .eq("id", application_id)
        .execute()
    )

    if not application_result.data:
        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    application = application_result.data[0]

    # Student can upload only to own application
    if (
        current_user["role"] == "student"
        and application["student_id"] != current_user["id"]
    ):
        raise HTTPException(
            status_code=403,
            detail="You cannot upload to this application"
        )

    # =====================================================
    # 2. CHECK PROGRAM DOCUMENT
    # =====================================================

    program_document_result = (
        supabase
        .table("program_documents")
        .select("*")
        .eq("id", program_document_id)
        .execute()
    )

    if not program_document_result.data:
        raise HTTPException(
            status_code=404,
            detail="Program document not found"
        )

    program_document = program_document_result.data[0]

    # =====================================================
    # 3. CHECK DOCUMENT BELONGS TO APPLICATION PROGRAM
    # =====================================================

    if (
        program_document["program_id"]
        != application["program_id"]
    ):
        raise HTTPException(
            status_code=400,
            detail="This document requirement does not belong to the application's program"
        )

    # =====================================================
    # 4. CHECK FILE
    # =====================================================

    filename = file.filename or ""

    extension = os.path.splitext(
        filename
    )[1].lower()

    allowed_extensions = [
        ".pdf",
        ".jpg",
        ".png"
    ]

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail="Only PDF, JPG and PNG files are allowed"
        )

    # =====================================================
    # 5. READ FILE
    # =====================================================

    file_content = file.file.read()

    # Maximum 5 MB
    max_size = 5 * 1024 * 1024

    if len(file_content) > max_size:
        raise HTTPException(
            status_code=400,
            detail="File size must be 5 MB or less"
        )

    # =====================================================
    # 6. FILE TYPE
    # =====================================================

    if extension == ".pdf":
        file_type = "PDF"

    elif extension == ".jpg":
        file_type = "JPG"

    else:
        file_type = "PNG"

    # =====================================================
    # 7. UNIQUE FILE NAME
    # =====================================================

    unique_filename = (
        f"{application_id}/"
        f"{uuid4()}_{filename}"
    )

    # =====================================================
    # 8. UPLOAD TO SUPABASE STORAGE
    # =====================================================

    try:

        supabase.storage.from_(
            STORAGE_BUCKET
        ).upload(
            unique_filename,
            file_content,
            {
                "content-type": (
                    file.content_type
                    or "application/octet-stream"
                )
            }
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"File upload failed: {str(e)}"
        )

    # =====================================================
    # 9. INSERT DOCUMENT INTO DATABASE
    # =====================================================

    document_data = {
        "application_id": application_id,
        "program_document_id": program_document_id,
        "student_id": application["student_id"],
        "file_name": filename,
        "file_path": unique_filename,
        "status": "Pending"
    }

    try:

        result = (
            supabase
            .table("documents")
            .insert(document_data)
            .execute()
        )

    except Exception as e:

        # If database insert fails,
        # remove uploaded file from storage

        try:

            supabase.storage.from_(
                STORAGE_BUCKET
            ).remove([
                unique_filename
            ])

        except Exception as storage_error:

            print(
                f"Storage cleanup warning: {storage_error}"
            )

        raise HTTPException(
            status_code=500,
            detail=f"Document database insert failed: {str(e)}"
        )

    if not result.data:

        raise HTTPException(
            status_code=500,
            detail="Document record creation failed"
        )

    created_document = result.data[0]

    # =====================================================
    # 10. SEND DATA TO n8n
    # =====================================================

    background_tasks.add_task(
        send_n8n_webhook,
        "document_uploaded",
        {
            "document": created_document,

            "application_id": application_id,

            "student_id": application["student_id"],

            "program_document_id": program_document_id,

            "file_name": filename,

            "file_type": file_type,

            "document_status": "Pending"
        }
    )

    # =====================================================
    # 11. RESPONSE
    # =====================================================

    return {
        "message": "Document uploaded successfully",

        "document": created_document,

        "file_type": file_type,

        "n8n_event": "document_uploaded"
    }


@app.get("/applications/{application_id}/documents")
def get_application_documents(
    application_id: str,
    current_user=Depends(get_current_user)
):

    result = (
        supabase
        .table("documents")
        .select("*")
        .eq("application_id", application_id)
        .execute()
    )

    return result.data


@app.patch("/documents/{document_id}/status")
def update_document_status(
    document_id: str,
    data: DocumentStatusData,
    background_tasks: BackgroundTasks,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    update_data = {
        "status": data.status
    }

    if data.status == "Rejected":
        update_data["rejection_reason"] = (
            data.rejection_reason
        )
    else:
        update_data["rejection_reason"] = None

    if data.status == "Verified":
        update_data["verified_at"] = (
            datetime.now(timezone.utc).isoformat()
        )
    else:
        update_data["verified_at"] = None

    result = (
        supabase
        .table("documents")
        .update(update_data)
        .eq("id", document_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    updated_document = result.data[0]

    background_tasks.add_task(
        send_n8n_webhook,
        "document_status_changed",
        {
            "document": updated_document,
            "new_status": data.status,
            "rejection_reason": data.rejection_reason
        }
    )

    return updated_document


@app.delete("/documents/{document_id}")
def delete_document(
    document_id: str,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    result = (
        supabase
        .table("documents")
        .select("*")
        .eq("id", document_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    document = result.data[0]

    # Delete storage file
    try:
        supabase.storage.from_(
            STORAGE_BUCKET
        ).remove([
            document["file_path"]
        ])
    except Exception as e:
        print(
            f"Storage delete warning: {e}"
        )

    # Delete DB record
    delete_result = (
        supabase
        .table("documents")
        .delete()
        .eq("id", document_id)
        .execute()
    )

    return {
        "message": "Document deleted successfully"
    }


# =========================================================
# NOTES
# =========================================================

@app.post("/notes")
def create_note(
    data: NoteData,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    note = data.model_dump()

    if current_user["role"] == "counselor":
        note["counselor_id"] = current_user["id"]

    result = (
        supabase
        .table("notes")
        .insert(note)
        .execute()
    )

    return result.data[0]


@app.get("/leads/{lead_id}/notes")
def get_lead_notes(
    lead_id: str,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    result = (
        supabase
        .table("notes")
        .select("*")
        .eq("lead_id", lead_id)
        .order("created_at", desc=True)
        .execute()
    )

    return result.data


@app.delete("/notes/{note_id}")
def delete_note(
    note_id: str,
    current_user=Depends(
        require_roles("admin", "counselor")
    )
):

    result = (
        supabase
        .table("notes")
        .delete()
        .eq("id", note_id)
        .execute()
    )

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Note not found"
        )

    return {
        "message": "Note deleted successfully"
    }
