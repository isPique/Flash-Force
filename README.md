# Flash Force Hash Cracker

- Flash Force is a powerful and efficient tool designed to crack password hashes using either a wordlist or a brute-force attack.
- It supports cracking SHA-256 and MD5 hashes and can leverage multiple CPU cores to speed up the process.
- The tool can save and resume sessions, making it practical for lengthy cracking attempts.

## Brute-Force working principle

```python
pool = multiprocessing.Pool(processes = multiprocessing.cpu_count())
```

- By utilizing all available CPU cores, the script can optimize the parallelization of a brute-force attack by distributing the workload across multiple processes. Each process is responsible for calculating the hash of a specific combination of characters, allowing them to run concurrently. This parallel processing enables the script to perform multiple hash calculations simultaneously, leading to a significant speedup in the overall execution time compared to a single-threaded approach. By fully leveraging the CPU's capabilities, the brute-force process becomes much more efficient, potentially reducing the time required to complete the task.

## Usage

1. Clone the repository:

    ```bash
    git clone https://github.com/isPique/Flash-Force.git
    ```

2. Navigate to the project directory:

    ```bash
    cd Flash-Force
    ```

3. Run the script:

    ```bash
    python3 FlashForce.py
    ```

# What makes it different

- I realized that nobody is using generators when reading a wordlist. Using generators can speed up file operations and improve a function's run time by at least 2-3 times.

- For example, the `read_wordlist` function. It acts as a generator, meaning that it doesn't load the entire file into memory at once. Instead, it reads and processes one line at a time, yielding each line as it is requested. This evaluation means that the function can handle very large files without consuming a lot of memory, as it only keeps one line in memory at a time.

- Using `for` loops when generating combinations and reading the wordlist. `for` loops are much faster than `while` loops!

- You can use either [Cython](https://cython.org/) or [Python](https://www.python.org/) to run the script, but I recommend Cython because it's way much faster than Python.

> [!NOTE]
> **You can modify the `chunk_size` variable to adjust the number of password attempts processed at once.**

# Speed Dominance - Cythonizing the script

- Cython is a superset of Python designed to give C-like performance with code that is written mostly in Python. Used primarily to optimize Python code by compiling it to C, which can significantly increase execution speed, especially in CPU-bound tasks.

- Cython code can include both Python and C syntax, allowing for more granular control over performance.

### How to cythonize?

  1. Navigate to the "Cythonized" directory:
  
      ```bash
      cd Cythonized
      ```
  
  2. Compile the Cython code into a shared object file that can be imported into Python:
  
      ```bash
      python setup.py build_ext --inplace
      ```
  
  3. Run the compiled Cython code:
  
     ```bash
     python -c "import FlashForce; FlashForce.main()"
     ```

## Wordlist Attack
> [!IMPORTANT]
> **Remember that the speed of this tool depends on your CPU's power!**

But even so, as you can see below, the script read 14.3 million lines of passwords in just 29 seconds! And it's just a virtual machine with only 2 CPU cores!!

![Wordlist Attack](https://github.com/isPique/Flash-Force/blob/main/Images/Wordlist%20Attack.png)

- Wordlist mentioned above: [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)

## Brute-Force Attack
![Brute-Force Attack](https://github.com/isPique/Flash-Force/blob/main/Images/Brute-Force%20Attack.png)

> [!WARNING]
> ***Use this tool responsibly and only for legitimate purposes!***

## To-Do
- [ ] Add More hashing algorithms
- [ ] Auto detect hash
- [ ] GPU support
