from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


# =========================
# AUTH
# =========================

class SignupData(BaseModel):
    full_name: str
    email: EmailStr
    phone: Optional[str] = None
    password: str
    role: str = "student"


class LoginData(BaseModel):
    email: EmailStr
    password: str


# =========================
# LEADS
# =========================

class LeadData(BaseModel):
    full_name: str
    email: EmailStr
    phone: str
    city: Optional[str] = None
    country: Optional[str] = None
    study_level: Optional[str] = None
    source: str
    stage: str = "New"
    lost_reason: Optional[str] = None
    counselor_id: Optional[str] = None


class LeadStageData(BaseModel):
    stage: str
    lost_reason: Optional[str] = None


# =========================
# FOLLOW UPS
# =========================

class FollowUpData(BaseModel):
    lead_id: str
    counselor_id: str
    task: str
    due_date: datetime


class FollowUpUpdate(BaseModel):
    completed: bool


# =========================
# UNIVERSITIES
# =========================

class UniversityData(BaseModel):
    name: str
    country: str
    city: Optional[str] = None


# =========================
# PROGRAMS
# =========================

class ProgramData(BaseModel):
    university_id: str
    name: str
    level: Optional[str] = None
    intake: Optional[str] = None
    application_deadline: date


# =========================
# PROGRAM DOCUMENTS
# =========================

class ProgramDocumentData(BaseModel):
    program_id: str
    document_name: str
    required: bool = True


# =========================
# APPLICATIONS
# =========================

class ApplicationData(BaseModel):
    student_id: str
    lead_id: Optional[str] = None
    program_id: str
    status: str = "Draft"


class ApplicationStatusData(BaseModel):
    status: str


# =========================
# DOCUMENTS
# =========================

class DocumentStatusData(BaseModel):
    status: str
    rejection_reason: Optional[str] = None


# =========================
# NOTES
# =========================

class NoteData(BaseModel):
    lead_id: str
    counselor_id: str
    note: str

