"""
WebShield Course Models

Pydantic models for the course management system.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class DifficultyLevel(str, Enum):
    """Course difficulty levels"""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class ContentType(str, Enum):
    """Lesson content types"""

    VIDEO = "video"
    TEXT = "text"
    INTERACTIVE = "interactive"
    QUIZ = "quiz"


class QuestionType(str, Enum):
    """Quiz question types"""

    MULTIPLE_CHOICE = "multiple_choice"
    TRUE_FALSE = "true_false"
    FILL_BLANK = "fill_blank"


# ============================================
# Course Models
# ============================================


class CourseBase(BaseModel):
    """Base course model with common fields"""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    difficulty_level: DifficultyLevel = DifficultyLevel.BEGINNER
    duration_minutes: int = Field(default=60, ge=0)
    thumbnail_url: Optional[str] = None
    instructor_name: str = Field(default="WebShield Team", max_length=100)
    category: str = Field(default="security", max_length=50)


class Course(CourseBase):
    """Full course model"""

    course_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_published: bool = True
    enrollment_count: int = 0
    rating: float = Field(default=4.5, ge=0, le=5)

    class Config:
        from_attributes = True


class CourseCreate(CourseBase):
    """Model for creating a new course"""

    pass


# ============================================
# Module Models
# ============================================


class ModuleBase(BaseModel):
    """Base module model"""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    order_index: int = Field(default=0, ge=0)


class CourseModule(ModuleBase):
    """Full module model"""

    module_id: str
    course_id: str
    lessons: Optional[List["Lesson"]] = None

    class Config:
        from_attributes = True


class ModuleCreate(ModuleBase):
    """Model for creating a new module"""

    course_id: str


# ============================================
# Lesson Models
# ============================================


class LessonBase(BaseModel):
    """Base lesson model"""

    title: str = Field(..., min_length=1, max_length=255)
    content_type: ContentType = ContentType.TEXT
    content: Optional[str] = None
    video_url: Optional[str] = None
    duration_minutes: int = Field(default=10, ge=0)
    order_index: int = Field(default=0, ge=0)


class Lesson(LessonBase):
    """Full lesson model"""

    lesson_id: str
    module_id: str

    class Config:
        from_attributes = True


class LessonCreate(LessonBase):
    """Model for creating a new lesson"""

    module_id: str


# ============================================
# Enrollment Models
# ============================================


class EnrollmentRequest(BaseModel):
    """Request model for course enrollment"""

    user_email: str = Field(..., min_length=1)
    course_id: str = Field(..., min_length=1)


class Enrollment(BaseModel):
    """Full enrollment model"""

    enrollment_id: str
    user_email: str
    course_id: str
    enrolled_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress_percentage: float = Field(default=0.0, ge=0, le=100)
    last_accessed: Optional[datetime] = None

    # Optional joined fields
    title: Optional[str] = None
    thumbnail_url: Optional[str] = None
    difficulty_level: Optional[str] = None

    class Config:
        from_attributes = True


# ============================================
# Progress Models
# ============================================


class ProgressUpdate(BaseModel):
    """Request model for updating lesson progress"""

    user_email: str = Field(..., min_length=1)
    lesson_id: str = Field(..., min_length=1)
    completed: bool = False
    time_spent_seconds: int = Field(default=0, ge=0)
    quiz_score: Optional[float] = Field(default=None, ge=0, le=100)


class LessonProgress(BaseModel):
    """Full lesson progress model"""

    progress_id: str
    user_email: str
    lesson_id: str
    completed: bool = False
    completed_at: Optional[datetime] = None
    time_spent_seconds: int = 0
    quiz_score: Optional[float] = None
    notes: Optional[str] = None

    class Config:
        from_attributes = True


# ============================================
# Quiz Models
# ============================================


class QuizOptionBase(BaseModel):
    """Base quiz option model"""

    option_text: str = Field(..., min_length=1)
    is_correct: bool = False
    order_index: int = Field(default=0, ge=0)


class QuizOption(QuizOptionBase):
    """Full quiz option model"""

    option_id: str
    question_id: str

    class Config:
        from_attributes = True


class QuizQuestionBase(BaseModel):
    """Base quiz question model"""

    question_text: str = Field(..., min_length=1)
    question_type: QuestionType = QuestionType.MULTIPLE_CHOICE
    correct_answer: Optional[str] = None
    explanation: Optional[str] = None
    points: int = Field(default=1, ge=0)
    order_index: int = Field(default=0, ge=0)


class QuizQuestion(QuizQuestionBase):
    """Full quiz question model"""

    question_id: str
    lesson_id: str
    options: Optional[List[QuizOption]] = None

    class Config:
        from_attributes = True


class QuizSubmission(BaseModel):
    """Model for quiz submission"""

    user_email: str
    lesson_id: str
    answers: dict  # {question_id: selected_answer}


class QuizResult(BaseModel):
    """Model for quiz results"""

    score: float
    total_points: int
    earned_points: int
    passed: bool
    results: List[dict]  # Individual question results


# ============================================
# Achievement Models
# ============================================


class AchievementBase(BaseModel):
    """Base achievement model"""

    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    icon: str = Field(default="🏆", max_length=100)
    points: int = Field(default=10, ge=0)
    category: Optional[str] = Field(default=None, max_length=50)


class Achievement(AchievementBase):
    """Full achievement model"""

    achievement_id: str

    class Config:
        from_attributes = True


class UserAchievement(BaseModel):
    """Model for user's earned achievements"""

    user_achievement_id: str
    user_email: str
    achievement_id: str
    earned_at: Optional[datetime] = None

    # Optional joined fields
    name: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    points: Optional[int] = None

    class Config:
        from_attributes = True


# ============================================
# Certificate Models
# ============================================


class Certificate(BaseModel):
    """Model for course completion certificates"""

    certificate_id: str
    user_email: str
    course_id: str
    issued_at: Optional[datetime] = None
    certificate_url: Optional[str] = None
    verification_code: str

    class Config:
        from_attributes = True


# ============================================
# Composite Models
# ============================================


class CourseWithModules(Course):
    """Course model with nested modules and lessons"""

    modules: Optional[List[CourseModule]] = None


class UserLearningStats(BaseModel):
    """User's overall learning statistics"""

    user_email: str
    total_enrollments: int = 0
    completed_courses: int = 0
    total_time_spent_minutes: int = 0
    total_points: int = 0
    achievements_count: int = 0
    security_awareness_score: int = 0


class DashboardStats(BaseModel):
    """Dashboard statistics for courses"""

    total_courses: int = 0
    total_enrollments: int = 0
    average_completion_rate: float = 0.0
    popular_courses: List[Course] = []


# Update forward references
CourseModule.model_rebuild()
