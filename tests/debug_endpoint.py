
import asyncio
import httpx
import json

async def test_endpoint():
    url = "http://localhost:8000/api/email/scan-metadata"
    payload = {
        "email_metadata": {
            "sender_email": "test@gmail.com",
            "sender_name": "Test User",
            "subject": "Test Email",
            "links": ["https://example.com"],
            "attachment_hashes": [],
            "attachment_names": [],
            "attachments": [],
            "headers": {
                "spf": "pass",
                "dkim": "pass",
                "dmarc": "pass"
            }
        },
        "scan_type": "full"
    }

    async with httpx.AsyncClient() as client:
        try:
            print(f"Sending request to {url}...")
            response = await client.post(url, json=payload, timeout=30.0)
            print(f"Status: {response.status_code}")
            try:
                print("Response JSON:", json.dumps(response.json(), indent=2))
            except:
                print("Response Text:", response.text)
        except Exception as e:
            print("Request failed:", e)

if __name__ == "__main__":
    asyncio.run(test_endpoint())
