
from backend.email_routes import HeaderAnalysis

def test():
    print("Testing HeaderAnalysis mutability...")
    h = HeaderAnalysis()
    print("Created:", h)
    try:
        h.spf_status = "pass"
        print("Updated spf_status to pass")
    except Exception as e:
        print("FAIL:", e)

    try:
        h.gmail_api_verified = True
        print("Updated gmail_api_verified to True")
    except Exception as e:
        print("FAIL:", e)

if __name__ == "__main__":
    test()
