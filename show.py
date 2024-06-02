import asyncio
import ssl
from aiohttp import ClientSession, TCPConnector
from mnemonic import Mnemonic
import bip32utils
from tronpy.keys import PrivateKey

# Function to generate a Tron address
def generate_tron_address(private_key):
    private_key_obj = PrivateKey(private_key)
    tron_address = private_key_obj.public_key.to_base58check_address()
    return tron_address

# Asynchronous function to get Tron balance
async def get_tron_balance(session, address):
    url = f"https://api.trongrid.io/v1/accounts/{address}"
    async with session.get(url, ssl=False) as response:  # Disable SSL verification
        if response.status == 200:
            data = await response.json()
            if data['data']:
                balance_sun = data['data'][0].get('balance', 0)
                balance_trx = balance_sun / 1e6
                return balance_trx
    return 0

# Function to save mnemonic and address to file
def save_to_file(mnemonic, address):
    with open("gg.txt", "a") as file:
        file.write(f"Mnemonic: {mnemonic}\nAddress: {address}\n\n")

# Main loop to generate mnemonics and check balances
async def main_loop():
    batch_size = 50000  # Increased batch size for better performance
    request_delay = 0.001  # Reduced delay between requests (adjust based on API rate limits)

    async with ClientSession(connector=TCPConnector(ssl=False)) as session:  # Disable SSL verification
        while True:
            try:
                # Generate a batch of mnemonics
                mnemonics = []
                for _ in range(batch_size):
                    mnemo = Mnemonic("english")
                    words = mnemo.generate(strength=128)
                    mnemonics.append(words)

                print(f"Generated {batch_size} mnemonics.")

                # Derive Tron addresses from mnemonics
                tron_addresses = []
                for words in mnemonics:
                    seed = Mnemonic("english").to_seed(words)
                    root_key = bip32utils.BIP32Key.fromEntropy(seed)
                    tron_child_key = root_key.ChildKey(195).ChildKey(0).ChildKey(0).ChildKey(0)
                    tron_private_key = tron_child_key.PrivateKey()
                    tron_address = generate_tron_address(tron_private_key)
                    tron_addresses.append(tron_address)
                    print(f"Derived Tron address: {tron_address}")  # Print the derived address

                print(f"Derived {len(tron_addresses)} Tron addresses.")

                # Check balances for Tron addresses concurrently
                balance_tasks = []
                for tron_address in tron_addresses:
                    balance_task = asyncio.create_task(get_tron_balance(session, tron_address))
                    balance_tasks.append(balance_task)
                    await asyncio.sleep(request_delay)  # Delay between requests

                balances = await asyncio.gather(*balance_tasks)

                print(f"Retrieved balances for {len(balances)} addresses.")

                # Process balances and save non-zero balances
                non_zero_count = 0
                for i, balance_tron in enumerate(balances):
                    if balance_tron > 0:
                        print(f"Non-zero balance found! Saving mnemonic and address.")
                        save_to_file(mnemonics[i], tron_addresses[i])
                        non_zero_count += 1

                print(f"Found {non_zero_count} addresses with non-zero balances.")

            except Exception as e:
                print(f"An error occurred in the main loop: {e}")
                await asyncio.sleep(1)  # Adjust the delay as needed

if __name__ == "__main__":
    asyncio.run(main_loop())
