
import asyncio
import logging
from backend.email_routes import analyze_headers, EmailHeaders

# Configure logging
logging.basicConfig(level=logging.ERROR)

async def test():
    print("Testing analyze_headers specific cases...")

    print("\n--- Case 1: All valid ---")
    try:
        res = await analyze_headers(EmailHeaders(spf="pass"), "test@gmail.com")
        print("Success")
    except Exception as e:
        print("FAIL:", e)
        import traceback
        traceback.print_exc()

    print("\n--- Case 2: Headers is None ---")
    try:
        res = await analyze_headers(None, "test@gmail.com")
        print("Success")
    except Exception as e:
        print("FAIL:", e)
        import traceback
        traceback.print_exc()

    print("\n--- Case 3: Sender is empty string ---")
    try:
        res = await analyze_headers(EmailHeaders(spf="pass"), "")
        print("Success")
    except Exception as e:
        print("FAIL:", e)
        import traceback
        traceback.print_exc()

    print("\n--- Case 4: Sender is None ---")
    try:
        res = await analyze_headers(EmailHeaders(spf="pass"), None)
        print("Success")
    except Exception as e:
        print("FAIL:", e)
        import traceback
        traceback.print_exc()

    print("\n--- Case 5: Both None ---")
    try:
        res = await analyze_headers(None, None)
        print("Success")
    except Exception as e:
        print("FAIL:", e)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
