## afl-btmin

Use backtrace to minimize crashes.

Python >= 3.8 is required and I suggest disabling other gdb plugins, i.e. keeping the `~/.gdbinit` clean.

Usage:

```bash
echo "source /path/to/repo/afl-btmin-gdb.py" >> ~/.gdbinit
python3 afl-btmin --afl afl_output_dir --output unique_crashes -- fuzz_program @@
```
