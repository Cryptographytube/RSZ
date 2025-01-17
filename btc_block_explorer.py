import json
from urllib.request import urlopen
import time

# List of APIs for redundancy
API_LIST = [
    "https://blockchain.info/rawaddr/{address}?offset={offset}",
    "https://api.blockchair.com/bitcoin/dashboards/address/{address}?offset={offset}"
]

def fetch_data_with_pagination(api_url, address):
    """Fetch all transactions for an address, dynamically handling pagination."""
    transactions = []
    offset = 0

    while True:
        try:
            # Format the URL with the address and offset
            url = api_url.format(address=address, offset=offset)
            print(f"Fetching data: {url}")
            
            # Fetch data from the API
            response = urlopen(url, timeout=30)
            data = json.loads(response.read().decode('utf-8'))

            # Extract transactions from API response
            if "blockchain.info" in api_url:
                # Blockchain.info response structure
                txs = data.get('txs', [])
                transactions.extend(txs)
                if not txs:  # Stop if no more transactions are returned
                    break
            elif "blockchair.com" in api_url:
                # Blockchair response structure
                txs = data.get('data', {}).get(address, {}).get('transactions', [])
                transactions.extend(txs)
                if not txs:  # Stop if no more transactions are returned
                    break
            else:
                print(f"Unsupported API format for {api_url}")
                break

            # Increment offset for the next page
            offset += len(txs)

        except Exception as e:
            print(f"Error fetching data: {e}")
            break

    return transactions

def get_all_transactions(address):
    """Fetch transactions from multiple APIs, ensuring full coverage."""
    for api in API_LIST:
        try:
            transactions = fetch_data_with_pagination(api, address)
            if transactions:
                return transactions
        except Exception as e:
            print(f"Error with API {api}: {e}")
            continue  # Try the next API
    return []

def main():
    address = input("Enter Bitcoin address: ")
    transactions = get_all_transactions(address)

    if transactions:
        print(f"All transactions for address {address}:")
        for tx in transactions:
            tx_hash = tx.get('hash') or tx.get('transaction_hash')
            block_height = tx.get('block_height') or tx.get('block_id', "Unconfirmed")
            print(f"Transaction Hash: {tx_hash}, Block Height: {block_height}")
    else:
        print(f"No transactions found for address {address}. It might not have any transactions.")

if __name__ == "__main__":
    main()














