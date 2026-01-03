# WebShield Course Management Module
"""
This module provides the course management system for WebShield,
enabling educational content integration with the security platform.
"""

from .models import (
    Achievement,
    Course,
    CourseModule,
    CourseWithModules,
    Enrollment,
    EnrollmentRequest,
    Lesson,
    LessonProgress,
    ProgressUpdate,
    QuizOption,
    QuizQuestion,
    UserAchievement,
)
from .routes import course_router

__all__ = [
    "Course",
    "CourseModule",
    "Lesson",
    "Enrollment",
    "LessonProgress",
    "QuizQuestion",
    "QuizOption",
    "Achievement",
    "UserAchievement",
    "CourseWithModules",
    "EnrollmentRequest",
    "ProgressUpdate",
    "course_router",
]
