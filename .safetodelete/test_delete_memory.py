from zapv2 import ZAPv2
import time

# def delete_requests_in_range(zap: ZAPv2, n: int, m: int):
#     """
#     Deletes requests in the specified range (n to m) from ZAP.

#     :param zap: The ZAP API client instance.
#     :param n: The starting request ID (inclusive).
#     :param m: The ending request ID (inclusive).
#     """
#     print(f"[*] Deleting requests with IDs from {n} to {m}...")
    
#     # Fetch all the messages in the current session
#     all_msgs = zap.core.messages()
    
#     # Filter messages based on the ID range [n, m]
#     messages_to_delete = [m for m in all_msgs if n <= int(m["id"]) <= m]
    

#     if not messages_to_delete:
#         print(f"[!] No messages found in the range {n} to {m}.")
#         return
    
#     # Delete the filtered messages
#     deleted_count = 0
#     for message in messages_to_delete:
#         msg_id = message["id"]
#         try:
#             zap.core.delete_message(msg_id)  # Delete the message by ID
#             deleted_count += 1
#             print(f"[+] Deleted request with ID: {msg_id}")
#         except Exception as e:
#             print(f"[!] Failed to delete request with ID: {msg_id}. Error: {e}")
    
#     print(f"[*] Total deleted requests: {deleted_count}")

# def main():
#     # ZAP API connection
#     zap_url = "http://localhost:8080"  # ZAP URL
#     zap_api_key = "your_api_key"  # Your ZAP API key (if any)
    
#     zap = ZAPv2(apikey=None)

#     # Example: Deleting requests with IDs from 100 to 150
#     n = 500
#     m = 1000

#     delete_requests_in_range(zap, n, m)

# if __name__ == "__main__":
#     main()


def delete_requests_in_range(zap: ZAPv2, n: int, m: int):
    """
    Deletes requests in the specified range (n to m) from ZAP.

    :param zap: The ZAP API client instance.
    :param n: The starting request ID (inclusive).
    :param m: The ending request ID (inclusive).
    """
    print(f"[*] Deleting requests with IDs from {n} to {m}...")
    
    # Fetch all the messages in the current session
    all_msgs = zap.core.messages()
    
    # Filter messages based on the ID range [n, m]
    messages_to_delete = [msg for msg in all_msgs if n <= int(msg["id"]) <= m]

    if not messages_to_delete:
        print(f"[!] No messages found in the range {n} to {m}.")
        return
    
    # Delete the filtered messages
    deleted_count = 0
    for msg in messages_to_delete:
        msg_id = msg["id"]
        try:
            zap.core.delete_message(msg_id)  # Delete the message by ID
            deleted_count += 1
            print(f"[+] Deleted request with ID: {msg_id}")
        except Exception as e:
            print(f"[!] Failed to delete request with ID: {msg_id}. Error: {e}")
    
    print(f"[*] Total deleted requests: {deleted_count}")

def main():
    # ZAP API connection
    zap_url = "http://localhost:8080"  # ZAP URL
    zap_api_key = "your_api_key"  # Your ZAP API key (if any)
    
    zap = ZAPv2(apikey=None)

    # Example: Deleting requests with IDs from 500 to 1000
    n = 500
    m = 1000

    delete_requests_in_range(zap, n, m)

if __name__ == "__main__":
    main()
