"""
WebShield Course API Routes

FastAPI routes for course management, enrollment, and progress tracking.
"""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query

from .models import (
    Achievement,
    Course,
    CourseWithModules,
    Enrollment,
    EnrollmentRequest,
    ProgressUpdate,
    UserAchievement,
    UserLearningStats,
)

logger = logging.getLogger(__name__)

course_router = APIRouter(prefix="/api/courses", tags=["Courses"])


# ============================================
# Helper Functions
# ============================================


def get_db_connection():
    """Get database connection with proper error handling"""
    try:
        from ..db import get_mysql_connection

        conn = get_mysql_connection()
        if not conn:
            logger.error("Failed to get database connection")
            return None
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None


# ============================================
# Course Endpoints
# ============================================


@course_router.get("/", response_model=List[Course])
async def get_all_courses(
    difficulty: Optional[str] = Query(None, description="Filter by difficulty level"),
    category: Optional[str] = Query(None, description="Filter by category"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """
    Get all published courses with optional filtering.

    - **difficulty**: Filter by beginner, intermediate, or advanced
    - **category**: Filter by course category
    - **limit**: Maximum number of courses to return (default 50)
    - **offset**: Number of courses to skip (for pagination)
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        # Build query with optional filters
        query = "SELECT * FROM courses WHERE is_published = TRUE"
        params = []

        if difficulty:
            query += " AND difficulty_level = %s"
            params.append(difficulty)

        if category:
            query += " AND category = %s"
            params.append(category)

        query += " ORDER BY enrollment_count DESC, rating DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cursor.execute(query, params)
        courses = cursor.fetchall()

        return courses

    except Exception as e:
        logger.error(f"Error fetching courses: {e}")
        raise HTTPException(status_code=500, detail="Error fetching courses") from e
    finally:
        cursor.close()
        conn.close()


@course_router.get("/stats")
async def get_course_stats():
    """Get overall course statistics"""
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        # Total courses
        cursor.execute("SELECT COUNT(*) as total FROM courses WHERE is_published = TRUE")
        total_courses = cursor.fetchone()["total"]

        # Total enrollments
        cursor.execute("SELECT COUNT(*) as total FROM user_enrollments")
        total_enrollments = cursor.fetchone()["total"]

        # Average completion rate
        cursor.execute(
            """
            SELECT AVG(CASE WHEN completed_at IS NOT NULL THEN 100 ELSE progress_percentage END) as avg_completion
            FROM user_enrollments
        """
        )
        result = cursor.fetchone()
        avg_completion = result["avg_completion"] or 0

        # Popular courses
        cursor.execute(
            """
            SELECT * FROM courses
            WHERE is_published = TRUE
            ORDER BY enrollment_count DESC
            LIMIT 5
        """
        )
        popular = cursor.fetchall()

        return {
            "total_courses": total_courses,
            "total_enrollments": total_enrollments,
            "average_completion_rate": round(avg_completion, 2),
            "popular_courses": popular,
        }

    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail="Error fetching statistics") from e
    finally:
        cursor.close()
        conn.close()


@course_router.get("/{course_id}", response_model=CourseWithModules)
async def get_course_detail(course_id: str):
    """
    Get detailed course information including modules and lessons.

    - **course_id**: The unique identifier of the course
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        # Get course
        cursor.execute("SELECT * FROM courses WHERE course_id = %s", (course_id,))
        course = cursor.fetchone()

        if not course:
            raise HTTPException(status_code=404, detail="Course not found")

        # Get modules
        cursor.execute(
            """
            SELECT * FROM course_modules
            WHERE course_id = %s
            ORDER BY order_index
        """,
            (course_id,),
        )
        modules = cursor.fetchall()

        # Get lessons for each module
        for module in modules:
            cursor.execute(
                """
                SELECT * FROM lessons
                WHERE module_id = %s
                ORDER BY order_index
            """,
                (module["module_id"],),
            )
            module["lessons"] = cursor.fetchall()

        course["modules"] = modules
        return course

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching course detail: {e}")
        raise HTTPException(status_code=500, detail="Error fetching course details") from e
    finally:
        cursor.close()
        conn.close()


# ============================================
# Enrollment Endpoints
# ============================================


@course_router.post("/enroll")
async def enroll_in_course(enrollment: EnrollmentRequest):
    """
    Enroll a user in a course.

    Returns the enrollment ID if successful.
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        # Check if course exists
        cursor.execute("SELECT course_id FROM courses WHERE course_id = %s", (enrollment.course_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Course not found")

        # Check if already enrolled
        cursor.execute(
            """
            SELECT enrollment_id FROM user_enrollments
            WHERE user_email = %s AND course_id = %s
        """,
            (enrollment.user_email, enrollment.course_id),
        )

        existing = cursor.fetchone()
        if existing:
            return {"message": "Already enrolled", "enrollment_id": existing["enrollment_id"], "already_enrolled": True}

        # Create enrollment
        enrollment_id = str(uuid4())
        cursor.execute(
            """
            INSERT INTO user_enrollments (enrollment_id, user_email, course_id, enrolled_at, last_accessed)
            VALUES (%s, %s, %s, %s, %s)
        """,
            (enrollment_id, enrollment.user_email, enrollment.course_id, datetime.now(), datetime.now()),
        )

        # Increment enrollment count
        cursor.execute(
            """
            UPDATE courses
            SET enrollment_count = enrollment_count + 1
            WHERE course_id = %s
        """,
            (enrollment.course_id,),
        )

        conn.commit()

        # Check for first enrollment achievement
        await check_and_award_achievement(enrollment.user_email, "first_enrollment", cursor, conn)

        logger.info(f"User {enrollment.user_email} enrolled in course {enrollment.course_id}")

        return {"message": "Successfully enrolled", "enrollment_id": enrollment_id, "already_enrolled": False}

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.error(f"Error enrolling user: {e}")
        raise HTTPException(status_code=500, detail="Error processing enrollment") from e
    finally:
        cursor.close()
        conn.close()


@course_router.get("/user/{user_email}/enrollments", response_model=List[Enrollment])
async def get_user_enrollments(user_email: str):
    """
    Get all courses a user is enrolled in.

    - **user_email**: The user's email address
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT e.*, c.title, c.thumbnail_url, c.difficulty_level, c.duration_minutes
            FROM user_enrollments e
            JOIN courses c ON e.course_id = c.course_id
            WHERE e.user_email = %s
            ORDER BY e.last_accessed DESC
        """,
            (user_email,),
        )

        enrollments = cursor.fetchall()
        return enrollments

    except Exception as e:
        logger.error(f"Error fetching enrollments: {e}")
        raise HTTPException(status_code=500, detail="Error fetching enrollments") from e
    finally:
        cursor.close()
        conn.close()


# ============================================
# Progress Endpoints
# ============================================


@course_router.post("/progress")
async def update_lesson_progress(progress: ProgressUpdate):
    """
    Update a user's progress on a lesson.

    This is called as users complete lessons or take quizzes.
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        # Check if progress exists
        cursor.execute(
            """
            SELECT progress_id, completed, time_spent_seconds
            FROM lesson_progress
            WHERE user_email = %s AND lesson_id = %s
        """,
            (progress.user_email, progress.lesson_id),
        )

        existing = cursor.fetchone()

        if existing:
            # Update existing progress
            new_time = existing["time_spent_seconds"] + progress.time_spent_seconds
            cursor.execute(
                """
                UPDATE lesson_progress
                SET completed = %s,
                    time_spent_seconds = %s,
                    quiz_score = COALESCE(%s, quiz_score),
                    completed_at = CASE WHEN %s THEN %s ELSE completed_at END
                WHERE progress_id = %s
            """,
                (
                    progress.completed or existing["completed"],
                    new_time,
                    progress.quiz_score,
                    progress.completed,
                    datetime.now(),
                    existing["progress_id"],
                ),
            )
        else:
            # Create new progress record
            progress_id = str(uuid4())
            cursor.execute(
                """
                INSERT INTO lesson_progress
                (progress_id, user_email, lesson_id, completed, time_spent_seconds, quiz_score, completed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    progress_id,
                    progress.user_email,
                    progress.lesson_id,
                    progress.completed,
                    progress.time_spent_seconds,
                    progress.quiz_score,
                    datetime.now() if progress.completed else None,
                ),
            )

        # Update enrollment progress percentage
        await update_enrollment_progress(progress.user_email, progress.lesson_id, cursor)

        conn.commit()

        # Check for achievements
        if progress.completed:
            await check_and_award_achievement(progress.user_email, "first_lesson", cursor, conn)

            if progress.quiz_score and progress.quiz_score >= 100:
                await check_and_award_achievement(progress.user_email, "perfect_quiz", cursor, conn)

        return {"message": "Progress updated successfully"}

    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating progress: {e}")
        raise HTTPException(status_code=500, detail="Error updating progress") from e
    finally:
        cursor.close()
        conn.close()


async def update_enrollment_progress(user_email: str, lesson_id: str, cursor):
    """Update the overall enrollment progress based on completed lessons"""
    try:
        # Get the course for this lesson
        cursor.execute(
            """
            SELECT cm.course_id
            FROM lessons l
            JOIN course_modules cm ON l.module_id = cm.module_id
            WHERE l.lesson_id = %s
        """,
            (lesson_id,),
        )

        result = cursor.fetchone()
        if not result:
            return

        course_id = result["course_id"]

        # Calculate progress
        cursor.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM lessons l
                 JOIN course_modules cm ON l.module_id = cm.module_id
                 WHERE cm.course_id = %s) as total_lessons,
                (SELECT COUNT(*) FROM lesson_progress lp
                 JOIN lessons l ON lp.lesson_id = l.lesson_id
                 JOIN course_modules cm ON l.module_id = cm.module_id
                 WHERE cm.course_id = %s AND lp.user_email = %s AND lp.completed = TRUE) as completed_lessons
        """,
            (course_id, course_id, user_email),
        )

        stats = cursor.fetchone()
        if stats and stats["total_lessons"] > 0:
            progress = (stats["completed_lessons"] / stats["total_lessons"]) * 100

            completed_at = datetime.now() if progress >= 100 else None

            cursor.execute(
                """
                UPDATE user_enrollments
                SET progress_percentage = %s,
                    last_accessed = %s,
                    completed_at = COALESCE(completed_at, %s)
                WHERE user_email = %s AND course_id = %s
            """,
                (progress, datetime.now(), completed_at, user_email, course_id),
            )

    except Exception as e:
        logger.error(f"Error updating enrollment progress: {e}")


@course_router.get("/user/{user_email}/progress")
async def get_user_progress(user_email: str, course_id: Optional[str] = None):
    """
    Get a user's lesson progress.

    - **user_email**: The user's email address
    - **course_id**: Optionally filter by course
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        if course_id:
            cursor.execute(
                """
                SELECT lp.*, l.title as lesson_title, cm.title as module_title
                FROM lesson_progress lp
                JOIN lessons l ON lp.lesson_id = l.lesson_id
                JOIN course_modules cm ON l.module_id = cm.module_id
                WHERE lp.user_email = %s AND cm.course_id = %s
                ORDER BY cm.order_index, l.order_index
            """,
                (user_email, course_id),
            )
        else:
            cursor.execute(
                """
                SELECT lp.*, l.title as lesson_title
                FROM lesson_progress lp
                JOIN lessons l ON lp.lesson_id = l.lesson_id
                WHERE lp.user_email = %s
            """,
                (user_email,),
            )

        progress = cursor.fetchall()
        return progress

    except Exception as e:
        logger.error(f"Error fetching progress: {e}")
        raise HTTPException(status_code=500, detail="Error fetching progress") from e
    finally:
        cursor.close()
        conn.close()


# ============================================
# Achievement Endpoints
# ============================================


@course_router.get("/achievements", response_model=List[Achievement])
async def get_all_achievements():
    """Get all available achievements"""
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM achievements ORDER BY category, points")
        achievements = cursor.fetchall()
        return achievements

    except Exception as e:
        logger.error(f"Error fetching achievements: {e}")
        raise HTTPException(status_code=500, detail="Error fetching achievements") from e
    finally:
        cursor.close()
        conn.close()


@course_router.get("/user/{user_email}/achievements", response_model=List[UserAchievement])
async def get_user_achievements(user_email: str):
    """Get all achievements earned by a user"""
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT ua.*, a.name, a.description, a.icon, a.points, a.category
            FROM user_achievements ua
            JOIN achievements a ON ua.achievement_id = a.achievement_id
            WHERE ua.user_email = %s
            ORDER BY ua.earned_at DESC
        """,
            (user_email,),
        )

        achievements = cursor.fetchall()
        return achievements

    except Exception as e:
        logger.error(f"Error fetching user achievements: {e}")
        raise HTTPException(status_code=500, detail="Error fetching achievements") from e
    finally:
        cursor.close()
        conn.close()


async def check_and_award_achievement(user_email: str, achievement_type: str, cursor, conn):
    """Check if user qualifies for an achievement and award it"""
    try:
        # Map achievement types to conditions
        achievement_checks = {
            "first_enrollment": ("a1", "First Steps"),
            "first_lesson": ("a2", "Quick Learner"),
            "perfect_quiz": ("a3", "Quiz Master"),
            "course_complete": ("a4", "Course Crusher"),
        }

        if achievement_type not in achievement_checks:
            return

        achievement_id, _ = achievement_checks[achievement_type]

        # Check if already earned
        cursor.execute(
            """
            SELECT user_achievement_id FROM user_achievements
            WHERE user_email = %s AND achievement_id = %s
        """,
            (user_email, achievement_id),
        )

        if cursor.fetchone():
            return  # Already earned

        # Award achievement
        ua_id = str(uuid4())
        cursor.execute(
            """
            INSERT INTO user_achievements (user_achievement_id, user_email, achievement_id, earned_at)
            VALUES (%s, %s, %s, %s)
        """,
            (ua_id, user_email, achievement_id, datetime.now()),
        )

        conn.commit()
        logger.info(f"Awarded achievement {achievement_type} to {user_email}")

    except Exception as e:
        logger.error(f"Error awarding achievement: {e}")


# ============================================
# Stats Endpoints
# ============================================


@course_router.get("/user/{user_email}/stats", response_model=UserLearningStats)
async def get_user_learning_stats(user_email: str):
    """Get comprehensive learning statistics for a user"""
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        # Total enrollments
        cursor.execute(
            """
            SELECT COUNT(*) as total FROM user_enrollments WHERE user_email = %s
        """,
            (user_email,),
        )
        total_enrollments = cursor.fetchone()["total"]

        # Completed courses
        cursor.execute(
            """
            SELECT COUNT(*) as total FROM user_enrollments
            WHERE user_email = %s AND completed_at IS NOT NULL
        """,
            (user_email,),
        )
        completed_courses = cursor.fetchone()["total"]

        # Total time spent
        cursor.execute(
            """
            SELECT COALESCE(SUM(time_spent_seconds), 0) as total_seconds
            FROM lesson_progress WHERE user_email = %s
        """,
            (user_email,),
        )
        total_seconds = cursor.fetchone()["total_seconds"]

        # Achievement points
        cursor.execute(
            """
            SELECT COALESCE(SUM(a.points), 0) as total_points
            FROM user_achievements ua
            JOIN achievements a ON ua.achievement_id = a.achievement_id
            WHERE ua.user_email = %s
        """,
            (user_email,),
        )
        total_points = cursor.fetchone()["total_points"]

        # Achievement count
        cursor.execute(
            """
            SELECT COUNT(*) as count FROM user_achievements WHERE user_email = %s
        """,
            (user_email,),
        )
        achievements_count = cursor.fetchone()["count"]

        # Calculate security awareness score (0-100)
        # Based on: courses completed, lessons done, quiz scores, achievements
        score_components = {
            "courses": min(completed_courses * 20, 30),  # Max 30 points
            "time": min(total_seconds // 3600, 20),  # Max 20 points (1 per hour)
            "achievements": min(achievements_count * 5, 25),  # Max 25 points
            "enrollments": min(total_enrollments * 5, 25),  # Max 25 points
        }
        security_score = sum(score_components.values())

        return {
            "user_email": user_email,
            "total_enrollments": total_enrollments,
            "completed_courses": completed_courses,
            "total_time_spent_minutes": total_seconds // 60,
            "total_points": total_points,
            "achievements_count": achievements_count,
            "security_awareness_score": min(security_score, 100),
        }

    except Exception as e:
        logger.error(f"Error fetching user stats: {e}")
        raise HTTPException(status_code=500, detail="Error fetching statistics") from e
    finally:
        cursor.close()
        conn.close()


# ============================================
# Quiz Endpoints
# ============================================


@course_router.get("/lessons/{lesson_id}/quiz")
async def get_lesson_quiz(lesson_id: str):
    """Get quiz questions for a lesson"""
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        # Get questions
        cursor.execute(
            """
            SELECT question_id, question_text, question_type, points, order_index
            FROM quiz_questions
            WHERE lesson_id = %s
            ORDER BY order_index
        """,
            (lesson_id,),
        )
        questions = cursor.fetchall()

        # Get options for each question
        for question in questions:
            cursor.execute(
                """
                SELECT option_id, option_text, order_index
                FROM quiz_options
                WHERE question_id = %s
                ORDER BY order_index
            """,
                (question["question_id"],),
            )
            question["options"] = cursor.fetchall()

        return {"lesson_id": lesson_id, "questions": questions}

    except Exception as e:
        logger.error(f"Error fetching quiz: {e}")
        raise HTTPException(status_code=500, detail="Error fetching quiz") from e
    finally:
        cursor.close()
        conn.close()


@course_router.post("/lessons/{lesson_id}/quiz/submit")
async def submit_quiz(lesson_id: str, user_email: str, answers: dict):
    """
    Submit quiz answers and get results.

    - **answers**: Dictionary mapping question_id to selected answer
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor(dictionary=True)

        # Get questions with correct answers
        cursor.execute(
            """
            SELECT q.question_id, q.correct_answer, q.explanation, q.points,
                   o.option_id, o.option_text, o.is_correct
            FROM quiz_questions q
            LEFT JOIN quiz_options o ON q.question_id = o.question_id
            WHERE q.lesson_id = %s
        """,
            (lesson_id,),
        )

        rows = cursor.fetchall()

        # Process questions
        questions = {}
        for row in rows:
            q_id = row["question_id"]
            if q_id not in questions:
                questions[q_id] = {
                    "correct_answer": row["correct_answer"],
                    "explanation": row["explanation"],
                    "points": row["points"],
                    "options": [],
                }
            if row["option_id"]:
                questions[q_id]["options"].append(
                    {"option_id": row["option_id"], "option_text": row["option_text"], "is_correct": row["is_correct"]}
                )

        # Grade quiz
        total_points = 0
        earned_points = 0
        results = []

        for q_id, q_data in questions.items():
            total_points += q_data["points"]
            user_answer = answers.get(q_id)

            # Check if correct (by option_id or text)
            is_correct = False
            if q_data["options"]:
                for opt in q_data["options"]:
                    if opt["is_correct"] and (user_answer == opt["option_id"] or user_answer == opt["option_text"]):
                        is_correct = True
                        break
            else:
                is_correct = user_answer == q_data["correct_answer"]

            if is_correct:
                earned_points += q_data["points"]

            results.append(
                {
                    "question_id": q_id,
                    "is_correct": is_correct,
                    "explanation": q_data["explanation"],
                    "points_earned": q_data["points"] if is_correct else 0,
                }
            )

        score = (earned_points / total_points * 100) if total_points > 0 else 0

        # Update lesson progress with quiz score
        progress = ProgressUpdate(
            user_email=user_email,
            lesson_id=lesson_id,
            completed=score >= 70,  # Pass if 70% or higher
            time_spent_seconds=0,
            quiz_score=score,
        )
        await update_lesson_progress(progress)

        return {
            "score": round(score, 2),
            "total_points": total_points,
            "earned_points": earned_points,
            "passed": score >= 70,
            "results": results,
        }

    except Exception as e:
        logger.error(f"Error submitting quiz: {e}")
        raise HTTPException(status_code=500, detail="Error processing quiz submission") from e
    finally:
        cursor.close()
        conn.close()
