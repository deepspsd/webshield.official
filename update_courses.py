"""
Update courses in the database to the new course titles
"""
import sys
import logging
logging.basicConfig(level=logging.INFO)

# Add parent directory to path
sys.path.insert(0, 'd:\\webshield.copy\\webshield.copy')

from backend.db import get_mysql_connection

def update_courses():
    conn = get_mysql_connection()
    if not conn:
        print("Failed to connect to database")
        return False
    
    try:
        cursor = conn.cursor()
        
        # Delete existing courses
        cursor.execute('DELETE FROM courses')
        print("Deleted existing courses")
        
        # Insert new courses - Beginner, Intermediate, and Advanced
        cursor.execute("""
            INSERT INTO courses (course_id, title, description, difficulty_level, duration_minutes, instructor_name, enrollment_count, rating) 
            VALUES 
            -- Beginner Courses
            ('c1', 'Introduction to Cyber Security', 'Learn the fundamental concepts of cybersecurity, including threats, vulnerabilities, and basic protection techniques.', 'beginner', 120, 'WebShield Security Team', 5420, 4.8),
            ('c2', 'Ethical Hacking', 'Discover the world of ethical hacking. Learn penetration testing, vulnerability assessment, and security testing methodologies.', 'beginner', 90, 'WebShield Security Team', 3890, 4.9),
            ('c3', 'Cryptography', 'Understand encryption, decryption, hashing, and cryptographic protocols to secure data and communications.', 'beginner', 150, 'WebShield Security Team', 2150, 4.7),
            ('c4', 'Threats to Websites', 'Learn about common web threats including SQL injection, XSS, CSRF, and how to protect your websites from attacks.', 'beginner', 60, 'WebShield Security Team', 4200, 4.6),
            -- Intermediate Courses
            ('c5', 'Phishing Attacks', 'Master the identification and prevention of phishing attacks. Learn about email phishing, spear phishing, and social engineering tactics.', 'intermediate', 100, 'WebShield Security Team', 2850, 4.7),
            ('c6', 'Kali Linux Fundamentals', 'Get hands-on with Kali Linux, the leading platform for penetration testing and security auditing.', 'intermediate', 180, 'WebShield Security Team', 3200, 4.8),
            ('c7', 'Wire Shark for Network Monitoring', 'Learn to use Wireshark for network protocol analysis, packet capture, and traffic monitoring.', 'intermediate', 120, 'WebShield Security Team', 2650, 4.6),
            -- Advanced Courses
            ('c8', 'Introduction to System Security', 'Advanced course on operating system security, hardening techniques, and system-level protection mechanisms.', 'advanced', 200, 'WebShield Security Team', 1420, 4.9),
            ('c9', 'Protection from Browser Attacks', 'In-depth analysis of browser vulnerabilities, XSS, CSRF, clickjacking, and advanced browser security techniques.', 'advanced', 150, 'WebShield Security Team', 1650, 4.8),
            ('c10', 'Securing Android Devices', 'Comprehensive guide to Android security, app permissions, malware detection, and mobile device hardening.', 'advanced', 180, 'WebShield Security Team', 1890, 4.7)
        """)
        
        conn.commit()
        print("SUCCESS: Courses updated successfully!")
        print("")
        print("BEGINNER courses (4):")
        print("  1. Introduction to Cyber Security")
        print("  2. Ethical Hacking")
        print("  3. Cryptography")
        print("  4. Threats to Websites")
        print("")
        print("INTERMEDIATE courses (3):")
        print("  5. Phishing Attacks")
        print("  6. Kali Linux Fundamentals")
        print("  7. Wire Shark for Network Monitoring")
        print("")
        print("ADVANCED courses (3):")
        print("  8. Introduction to System Security")
        print("  9. Protection from Browser Attacks")
        print("  10. Securing Android Devices")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Error updating courses: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    update_courses()
