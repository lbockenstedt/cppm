from src.client import CPPMClient
from src.queries import CPPMQueries
import os
def main():
    # .env is loaded via CPPMClient import

    try:
        # Initialize Client
        client = CPPMClient()
        print(f"Connecting to CPPM at {client.host}...")

        # Initialize Query Module
        queries = CPPMQueries(client)

        # Example 1: Get a specific device by MAC
        # Replace with a real MAC from your environment to test
        test_mac = "00:11:22:33:44:55"
        print(f"Querying device info for {test_mac}...")
        device = queries.get_device_by_mac(test_mac)
        if device:
            print(f"Found device: {device}")
        else:
            print(f"No device found for MAC {test_mac}")

        # Example 2: List some endpoints
        print("Listing endpoints with filter {'vendor': 'Apple'}...")
        apple_devices = queries.list_endpoints({"vendor": "Apple"})
        print(f"Found {len(apple_devices)} Apple devices.")

        # Example 3: Get user sessions
        test_user = "admin"
        print(f"Querying sessions for user {test_user}...")
        sessions = queries.get_user_sessions(test_user)
        print(f"Found {len(sessions)} sessions.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
