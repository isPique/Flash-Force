from string import ascii_lowercase, ascii_uppercase, digits, punctuation
from multiprocessing import Pool, cpu_count
from signal import SIGINT, SIG_IGN, signal
from os import system, remove, name, path
from itertools import product, islice
from hashlib import sha256, md5
from pickle import dump, load
from time import perf_counter
from re import fullmatch
from sys import stdout

# Initialize the worker processes to ignore keyboard interrupts (SIGINT)
def init_worker():
    signal(SIGINT, SIG_IGN)

# Display the tool banner with ASCII art
def display_banner():
    system('cls' if name == 'nt' else 'clear')
    DEFAULT, GREEN, RED, YELLOW, BLINK, MAGENTA, BLUE = '\033[0m', '\033[1;92m', '\033[1;31m', '\033[1;33m', '\033[5m', '\033[1;35m', '\033[1;34m'

    print('''
{3} ███████████ ████                    █████         ███████████{0}
{3}░░███░░░░░░█░░███                   ░░███         ░░███░░░░░░█{0}
{3} ░███   █ ░  ░███   ██████    █████  ░███████      ░███   █ ░   ██████  ████████  ██████   ██████{0}
{3} ░███████    ░███  ░░░░░███  ███░░   ░███░░███     ░███████    ███░░███░░███░░███ ███░░███ ███░░███{0}
{3} ░███░░░█    ░███   ███████ ░░█████  ░███ ░███     ░███░░░█   ░███ ░███ ░███ ░░░ ░███ ░░░ ░███████{0}
{3} ░███  ░     ░███  ███░░███  ░░░░███ ░███ ░███     ░███  ░    ░███ ░███ ░███     ░███  ███░███░░░{0}
{3} █████       █████░░████████ ██████  ████ █████    █████      ░░██████  █████    ░░██████ ░░██████{0}
{3}░░░░░       ░░░░░  ░░░░░░░░ ░░░░░░  ░░░░ ░░░░░    ░░░░░        ░░░░░░  ░░░░░      ░░░░░░   ░░░░░░{0}

                                                                                    {6}~{3} isPique
                     {2}_______________________________________{0}
                    {2}/                                       \{0}
                    {2}\   {2}I wrote the fastest hash cracker!{2}   /{0}
          {3}.    ___{0}   {2}\____   ______________________________/{0}
              {3}/   ＼{0}      {2}\ノ{0}
            {3}∠)_ ● /  {5}/\ /\{0}                         {6}~{3} GitHub: {1}https://github.com/isPique
               {3}/ /__{5}( • ω •){3}__{0}                   {6}~{3} Insta: {1}https://instagram.com/omrefarukk
              {3}(       {5}∪ ∪{3}     ){0}
            {6}~~~~~~~~~~~~~~~~~~~~~~~~~{0}
          '''.format(DEFAULT, GREEN, RED, YELLOW, BLINK, MAGENTA, BLUE))

# Warn the user about CPU usage
def warn_user(cores):
    print(f"\n\033[1;91m[!] The attack will use {cores} CPU cores, which may impact your system's performance.\033[0m")
    print(f"\033[1;91m[!] Press Ctrl + C to stop/save the session.\033[0m\n")

# Format the elapsed time in hours, minutes, and seconds
def format_time(seconds):
    hours, rem = divmod(seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"

# Hash a password attempt and check if it matches the target hash
def hash_and_check(args):
    attempt, hash, hash_type = args
    hash_func = sha256 if hash_type == '1' else md5
    return attempt if hash_func(attempt.encode()).hexdigest() == hash else None

# Generate combinations of characters for brute-force attack
def generate_combinations(characters, length, chunk_size, start_position = 0):
    combinations = product(characters, repeat = length)  # Create all possible combinations
    for _ in range(start_position):
        next(combinations)  # Skip combinations until start_position
    for chunk in iter(lambda: list(islice(combinations, chunk_size)), []):  # Yield chunks of combinations
        if chunk:
            yield chunk

# Read the wordlist file line by line, starting from a specific line
def read_wordlist(filepath, start_line = 0):
    with open(filepath, 'r', encoding = 'utf-8', errors = 'ignore') as file:
        for _ in range(start_line):
            next(file)  # Skip lines until start_line
        yield from file  # Yield each line from the file

# Save the current state of the attack to a file
def save_state(filename, state):
    with open(filename, 'wb') as file:
        dump(state, file)

# Load the saved state from the file
def load_state(filename):
    with open(filename, 'rb') as file:
        return load(file)

# Main logic
def main():
    try:
        chunk_size = 100000
        cores = 32 * cpu_count()  # Get the number of CPU cores
        bruteforce_state_file = 'bruteforce_state.pkl'  # File to save brute-force state
        wordlist_state_file = 'wordlist_state.pkl'  # File to save wordlist state

        display_banner()

        print("\033[1;93m----- Algorithms -----\n")
        print("    \033[1;34m[1] \033[2;32mSHA-256")
        print("    \033[1;34m[2] \033[2;32mMD5")
        print("    \033[1;34m[3] \033[2;32mExit\n")

        # Prompt user to select a hashing algorithm and get the target hash based on the selected algorithm
        hash_type = input("\033[1;34m[>] \033[1;92mSelect a hashing algorithm \xBB \033[0m\033[1;77m").strip()
        if hash_type not in ['1', '2', '3']:  # Validate user input
            print("\033[1;91m[-] Invalid algorithm selected. Exiting...\033[0m")
            return

        if hash_type == '1':
            target_hash = input("\033[1;34m[>] \033[1;92mEnter the target SHA-256 hash \xBB \033[0m\033[1;77m").strip().lower()
            if not fullmatch(r"[a-fA-F0-9]{64}", target_hash):  # Validate SHA-256 hash
                print("\033[1;91m[-] This is not an SHA-256 hash.\033[0m")
                return

        if hash_type == '2':
            target_hash = input("\033[1;34m[>] \033[1;92mEnter the target MD5 hash \xBB \033[0m\033[1;77m").strip().lower()
            if not fullmatch(r"[a-fA-F0-9]{32}", target_hash):  # Validate MD5 hash
                print("\033[1;91m[-] This is not an MD5 hash.\033[0m")
                return

        if hash_type == '3':
            print("\033[1;34m[*] Exiting...\033[0m")
            return

        # Check if the user wants to use a wordlist
        if input("\033[1;34m[>] \033[1;92mUse a wordlist? (y/n) \xBB \033[0m\033[1;77m").strip().lower() == 'y':
            wordlist_path = input("\033[1;34m[>] \033[1;92mEnter the wordlist file path \xBB \033[0m\033[1;77m").strip()

            if not path.exists(wordlist_path):  # Check if wordlist file exists
                print(f"\033[1;91m[-] Wordlist file '{wordlist_path}' not found. Exiting...\033[0m")
                return

            # Load or initialize wordlist state
            if path.exists(wordlist_state_file) and input("\033[1;34m[>] \033[1;92mResume previous wordlist session? (y/n): \xBB \033[0m\033[1;77m").strip().lower() == 'y':
                state = load_state(wordlist_state_file)
                start_line, start_time = state['start_line'], state['start_time']
                warn_user(cores)
                total_lines = sum(1 for _ in open(wordlist_path, 'r', encoding = 'utf-8', errors = 'ignore'))
                print(f"\033[1;34m[*] Total lines: \033[1;93m{total_lines}\033[0m")
                print(f"\033[1;34m[*] Resuming from line: \033[1;93m{start_line}\033[0m\n")
                start_time = perf_counter() - start_time
            else:
                if path.exists(wordlist_state_file):
                    remove(wordlist_state_file)
                print(f"\033[1;34m[*] Starting new session...\033[0m")
                warn_user(cores)
                start_line = 0
                total_lines = sum(1 for _ in open(wordlist_path, 'r', encoding = 'utf-8', errors = 'ignore'))
                print(f"\033[1;34m[*] Starting wordlist attack...\033[0m")
                print(f"\033[1;34m[*] Total lines: \033[1;93m{total_lines}\033[0m\n")
                start_time = perf_counter()

            # Read wordlist and check for passwords
            current_line = start_line
            with Pool(processes = cores, initializer = init_worker) as pool:
                try:
                    wordlist_gen = read_wordlist(wordlist_path, start_line = start_line)
                    for chunk in iter(lambda: list(islice(wordlist_gen, chunk_size)), []):
                        results = pool.map(hash_and_check, ((line.strip(), target_hash, hash_type) for line in chunk))
                        for result in results:
                            current_line += 1
                            if result:
                                time_taken = perf_counter() - start_time
                                print(f"\n\n\033[1;92m[+] Hash Cracked!\033[0m")
                                print(f"\033[1;92m[+] Password: \033[1;93m{result}\033[0m")
                                print(f"\033[1;92m[+] Time taken: \033[1;93m{format_time(time_taken)}\033[0m")
                                print(f"\033[1;92m[+] Found at line: \033[1;93m{current_line}\033[0m")
                                if path.exists(wordlist_state_file):
                                    remove(wordlist_state_file)
                                return

                        stdout.write(f"\r\033[1;34m[*] Max time to crack the hash: \033[1;93m{format_time(((perf_counter() - start_time) / current_line if current_line > 0 else 0) * (total_lines - current_line))}")
                        stdout.flush()

                except KeyboardInterrupt:
                    pool.close()
                    pool.join()
                    print(f"\n\n\033[1;91m[-] Aborted.\033[0m")
                    if input("\033[1;34m[>] \033[1;92mSave session for later? (y/n) \xBB \033[0m\033[1;77m").strip().lower() == 'y':
                        start_time = perf_counter() - start_time
                        save_state(wordlist_state_file, {'start_line': current_line, 'start_time': start_time})
                        print(f"\033[1;34m[*] Session saved.\033[0m")
                    else:
                        print("\033[1;34m[*] Session not saved.\033[0m")
                    return

                print("\n\n\033[1;91m[-] Could not crack the target hash using this wordlist.\033[0m")
                if path.exists(wordlist_state_file):
                    remove(wordlist_state_file)
                if input("\033[1;34m[>] \033[1;92mWould you like to use brute-force attack? (y/n) \xBB \033[0m\033[1;77m").strip().lower() != 'y':
                    print("\033[1;34m[*] Alright, exiting...\033[0m")
                    return

        print(f"\n\033[1;34m[*] Using raw brute-force...\033[0m")

        # Load or initialize brute-force state
        if path.exists(bruteforce_state_file) and input("\n\033[1;34m[>] \033[1;92mResume previous brute-force session? (y/n): \xBB \033[0m\033[1;77m").strip().lower() == 'y':
            state = load_state(bruteforce_state_file)
            chars, length, start_position, start_time, processed_combinations, max_length = state['chars'], state['length'], state['start_position'], state['start_time'], state['processed_combinations'], state['max_length']
            start_time = perf_counter() - start_time
            print(f"\n\033[1;34m[*] Resuming from length \033[1;93m{length}\033[1;34m and position \033[1;93m{start_position}\033[0m")
        else:
            if path.exists(bruteforce_state_file):
                remove(bruteforce_state_file)

            print(f"\033[1;34m[*] Starting new session...\033[0m\n")

            try: length = int(input("\033[1;34m[>] \033[1;92mMinimum password length? (default is 1) \xBB \033[0m\033[1;77m") or 1)
            except ValueError: length = 1

            try: max_length = int(input("\033[1;34m[>] \033[1;92mMaximum password length? (default is 25) \xBB \033[0m\033[1;77m") or 25)
            except ValueError: max_length = 25

            # Get the character set to use in the brute-force attack
            chars = ""

            if input("\033[1;34m[>] \033[1;92mInclude lowercase letters? (y/n): \xBB \033[0m\033[1;77m").lower() == "y":
                chars += ascii_lowercase
            if input("\033[1;34m[>] \033[1;92mInclude uppercase letters? (y/n): \xBB \033[0m\033[1;77m").lower() == "y":
                chars += ascii_uppercase
            if input("\033[1;34m[>] \033[1;92mInclude digits? (y/n): \xBB \033[0m\033[1;77m").lower() == "y":
                chars += digits
            if input("\033[1;34m[>] \033[1;92mInclude punctuation? (y/n): \xBB \033[0m\033[1;77m").lower() == "y":
                chars += punctuation

            if not chars:
                print("\033[1;91m[-] No characters selected. Exiting...\033[0m")
                return

            warn_user(cores)
            print(f"\033[1;34m[*] Starting brute-force attack...\033[0m\n")
            start_position = 0
            processed_combinations = 0
            start_time = perf_counter()

        print(f"\033[1;34m[*] Character Set: \033[1;93m{chars}\033[0m")
        print(f"\033[1;34m[*] Min Length: \033[1;93m{length}\033[0m")
        print(f"\033[1;34m[*] Max Length: \033[1;93m{max_length}\033[0m\n")

        # Check if any generated combinations matches the target hash
        with Pool(processes = cores, initializer = init_worker) as pool:
            for length in range(length, max_length + 1):  # Iterate over password lengths
                try:
                    total_combinations = len(chars) ** length
                    for chunk in generate_combinations(chars, length, chunk_size, start_position = start_position):
                        processed_combinations += len(chunk)
                        results = pool.map(hash_and_check, ((''.join(combination), target_hash, hash_type) for combination in chunk))
                        for result in results:
                            if result:
                                time_taken = perf_counter() - start_time
                                print(f"\n\n\n\033[1;92m[+] Hash cracked!\033[0m")
                                print(f"\033[1;92m[+] Password: \033[1;93m{result}\033[0m")
                                print(f"\033[1;92m[+] Time taken: \033[1;93m{format_time(time_taken)}\033[0m")
                                print(f"\033[1;92m[+] Total used combinations: \033[1;93m{total_combinations}\033[0m")
                                if path.exists(bruteforce_state_file):
                                    remove(bruteforce_state_file)
                                return

                        # Update the start position for the next chunk
                        start_position += len(chunk)
                        stdout.write(f"\033[1;34m[*] Attempting length: \033[1;93m{length}\n\033[1;34m[*] Estimated time remaining: \033[1;93m{format_time(((perf_counter() - start_time) / processed_combinations) * (total_combinations - start_position))}\033[0m\n")
                        stdout.flush()
                        stdout.write("\033[F" * 2)

                except KeyboardInterrupt:
                    pool.close()
                    pool.join()
                    print(f"\n\n\n\033[1;91m[-] Aborted.\033[0m")
                    if input("\033[1;34m[>] \033[1;92mSave session for later? (y/n) \xBB \033[0m\033[1;77m").strip().lower() == 'y':
                        start_time = perf_counter() - start_time
                        save_state(bruteforce_state_file, {'chars': chars, 'length': length, 'start_position': start_position, 'start_time': start_time, 'processed_combinations': processed_combinations, 'max_length': max_length})
                        print(f"\033[1;34m[*] Session saved.\033[0m")
                    else:
                        if path.exists(bruteforce_state_file):
                            remove(bruteforce_state_file)
                        print("\033[1;34m[*] Session not saved.\033[0m")
                    return

                # Reset start_position and increment length for the next round
                start_position = 0
                length += 1

            print(f"\n\n\n\033[1;91m[-] The target hash could not be cracked with this character set.\033[0m")

    except KeyboardInterrupt:
        print(f"\n\033[1;91m[-] Aborted.\033[0m")
        return

if __name__ == "__main__":
    main()