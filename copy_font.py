import shutil
import os

source = r"C:\Windows\Fonts\arial.ttf"
dest_dir = r"static\fonts"
dest_file = os.path.join(dest_dir, "arial.ttf")

if not os.path.exists(dest_dir):
    os.makedirs(dest_dir)

try:
    if os.path.exists(source):
        shutil.copy2(source, dest_file)
        print(f"Success: Copied {source} to {dest_file}")
    else:
        print(f"Error: Source font not found at {source}")
except Exception as e:
    print(f"Error copying font: {e}")
